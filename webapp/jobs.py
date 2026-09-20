"""
Background triage runner plus the DB helpers that turn triage findings into
incident-timeline rows.

One triage run at a time (single-user local tool, so no queue/broker): a module
level state dict guarded by a lock, a worker thread, and a cancel flag. The
worker opens its OWN sqlite connection - the Flask request connection lives on
`g` and is unusable outside a request.
"""
import json
import re
import sqlite3
import threading
import time

from . import settings_store
from .ingest import (
    INCIDENT_TABLE,
    TRIAGE_FINDING_TABLE,
    TRIAGE_RUN_TABLE,
    ensure_work_tables,
)

_lock = threading.Lock()
_state = {"status": "idle", "run_id": None, "stage": "", "done": 0, "total": 0,
          "message": "", "error": None, "started_at": None, "stats": None}
_cancel = threading.Event()


class RunInProgress(Exception):
    pass


def get_status():
    with _lock:
        return dict(_state)


def cancel():
    with _lock:
        running = _state["status"] == "running"
    if running:
        _cancel.set()
    return running


def _set(**kw):
    with _lock:
        _state.update(kw)


# ──────────────────────────────────────────────────────────────────────────────
# Incident-timeline writes (shared by the manual pin route and triage accept)
# ──────────────────────────────────────────────────────────────────────────────

def insert_incident(conn, *, sheet_name, source_row_id, timestamp, date_text, severity,
                    description, computer, fields, note="", parent_id=None):
    """Insert one row into the incident timeline and return its id. Does not commit.

    parent_id set means this is a sub-event of that row (triage evidence under its
    finding); it is grouped beneath the parent in the table and kept off the charts."""
    cur = conn.execute(
        f"INSERT INTO {INCIDENT_TABLE} "
        "(sheet_name, source_row_id, timestamp, date_text, severity, description, computer, "
        "fields_json, note, added_at, parent_id) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (sheet_name, source_row_id, timestamp, date_text, severity, description, computer,
         json.dumps(fields), note, time.time(), parent_id),
    )
    return cur.lastrowid


def delete_incidents(conn, ids):
    """Remove rows from the incident timeline (single or many). Does not commit.

    A triage finding that was accepted onto the timeline remembers the timeline
    rows it created. If its summary row is removed, the finding must go back to
    the review queue - otherwise it would keep claiming "added to timeline" and,
    being already decided, could never be added again. Removing only a finding's
    evidence rows leaves the finding as it was.

    Returns {"deleted": n, "findings_reopened": m}.
    """
    wanted = sorted({int(i) for i in ids})
    # Removing a finding must take its sub-events with it, or they are stranded with
    # a parent that no longer exists.
    children = set()
    for start in range(0, len(wanted), 500):
        chunk = wanted[start:start + 500]
        marks = ",".join("?" for _ in chunk)
        children.update(r[0] for r in conn.execute(
            f"SELECT id FROM {INCIDENT_TABLE} WHERE parent_id IN ({marks})", chunk))
    wanted = sorted(set(wanted) | children)

    existing = set()
    for start in range(0, len(wanted), 500):        # stay under SQLite's variable limit
        chunk = wanted[start:start + 500]
        marks = ",".join("?" for _ in chunk)
        existing.update(r[0] for r in conn.execute(
            f"SELECT id FROM {INCIDENT_TABLE} WHERE id IN ({marks})", chunk))
        conn.execute(f"DELETE FROM {INCIDENT_TABLE} WHERE id IN ({marks})", chunk)

    reopened = 0
    if existing:
        for row in conn.execute(
                f"SELECT id, incident_ids_json FROM {TRIAGE_FINDING_TABLE} "
                "WHERE status IN ('accepted', 'auto_accepted')").fetchall():
            try:
                made = json.loads(row[1] or "[]")
            except (TypeError, ValueError):
                continue
            if made and made[0] in existing:        # made[0] is the summary row
                conn.execute(
                    f"UPDATE {TRIAGE_FINDING_TABLE} SET status = 'pending', decided_at = NULL, "
                    "incident_ids_json = '[]' WHERE id = ?", (row[0],))
                reopened += 1
    return {"deleted": len(existing), "sub_events_deleted": len(children & existing),
            "findings_reopened": reopened}


def _fmt_ts(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts)) if ts is not None else "unknown"


def _sheet_tables(conn):
    """{sheet name: table name} from the cache metadata."""
    row = conn.execute("SELECT value FROM _meta WHERE key = 'sheets'").fetchone()
    return {s["name"]: s["table"] for s in json.loads(row[0])} if row else {}


def _full_row(conn, tables, sheet_name, row_id):
    """The complete source row behind a piece of evidence.

    A finding's stored evidence holds descriptions shortened for display, so
    pinning must go back to the report rather than copy those. Returns None when
    the row cannot be resolved (e.g. the sheet was renamed by a rebuild)."""
    table = tables.get(sheet_name)
    if not table or row_id is None:
        return None
    try:
        row = conn.execute(f'SELECT * FROM "{table}" WHERE _id = ?', (row_id,)).fetchone()
    except sqlite3.Error:
        return None
    if not row:
        return None
    d = dict(row)
    d.pop("_id", None)
    return d


def finding_to_dict(row):
    d = dict(row)
    for key in ("evidence_json", "incident_ids_json", "tool_trace_json"):
        if key not in d:
            continue
        try:
            d[key[:-5]] = json.loads(d.pop(key) or "[]")
        except (TypeError, ValueError):
            d[key[:-5]] = []
            d.pop(key, None)
    return d


def _evidence_line(conn, tables, e):
    """One evidence line for the incident note, using the full source row."""
    full = _full_row(conn, tables, e["sheet"], e["row_id"]) or {}
    date = full.get("Date and Time") or e["date"]
    rule = full.get("Detection Rule") or e["rule"]
    desc = full.get("Event Description") or e["description"]
    return " ".join(str(x) for x in (f"[{e['sheet']} #{e['row_id']}]", date, rule, desc) if x).strip()


def backfill_incident_parents(conn):
    """Link evidence rows pinned before sub-events existed to their finding.

    A finding records the rows it created as [summary, *evidence] in
    incident_ids_json, so the parentage is recoverable exactly. Rows that were
    since deleted are skipped, and rows that already have a parent are left alone.
    Restorative and idempotent. Returns the number of rows linked."""
    linked = 0
    try:
        rows = conn.execute(
            f"SELECT id, incident_ids_json FROM {TRIAGE_FINDING_TABLE} "
            "WHERE status IN ('accepted', 'auto_accepted')").fetchall()
    except sqlite3.Error:
        return 0
    for row in rows:
        try:
            made = json.loads(row[1] or "[]")
        except (TypeError, ValueError):
            continue
        if len(made) < 2:
            continue
        parent, kids = made[0], [int(k) for k in made[1:]]
        if not conn.execute(f"SELECT 1 FROM {INCIDENT_TABLE} WHERE id = ?", (parent,)).fetchone():
            continue                      # summary row gone; nothing to hang them on
        for start in range(0, len(kids), 500):
            chunk = kids[start:start + 500]
            marks = ",".join("?" for _ in chunk)
            cur = conn.execute(
                f"UPDATE {INCIDENT_TABLE} SET parent_id = ? "
                f"WHERE id IN ({marks}) AND parent_id IS NULL AND id != ?",
                [parent] + chunk + [parent])
            linked += cur.rowcount
    return linked


def repair_truncated_incidents(conn):
    """Restore full text on timeline rows pinned by older versions.

    Early builds copied a finding's display-shortened evidence into the pinned
    row, so stored fields could end in "[truncated]". Anything still pointing at
    a real report row is rebuilt from that row; rows whose source is gone are
    left untouched. Purely restorative - no row is removed and no note is lost.
    Returns the number of rows repaired.
    """
    previous_factory = conn.row_factory
    conn.row_factory = sqlite3.Row   # callers vary; this code needs named columns
    try:
        return _repair_truncated_incidents(conn)
    finally:
        conn.row_factory = previous_factory


def _repair_truncated_incidents(conn):
    tables = _sheet_tables(conn)
    repaired = 0
    for row in conn.execute(
            f"SELECT id, sheet_name, source_row_id, fields_json FROM {INCIDENT_TABLE}").fetchall():
        d = dict(row)
        if "[truncated]" not in (d.get("fields_json") or ""):
            continue
        try:
            fields = json.loads(d["fields_json"]) or {}
        except (TypeError, ValueError):
            continue

        full = _full_row(conn, tables, d["sheet_name"], d["source_row_id"])
        if full:
            # A pinned report row: take the real fields, keep our annotations.
            preserved = {k: v for k, v in fields.items()
                         if k in ("Source", "Finding") or k not in full}
            merged = dict(full)
            merged.update({k: v for k, v in preserved.items() if "[truncated]" not in str(v)})
        elif "[truncated]" in str(fields.get("Evidence") or ""):
            # A finding summary row: only its rendered Evidence list is damaged, and
            # each line still carries the "[Sheet #id]" reference needed to redraw it.
            merged = dict(fields)
            merged["Evidence"] = "\n".join(
                _redraw_evidence_line(conn, tables, line)
                for line in str(fields["Evidence"]).splitlines())
        else:
            continue

        conn.execute(f"UPDATE {INCIDENT_TABLE} SET fields_json = ? WHERE id = ?",
                     (json.dumps(merged), d["id"]))
        repaired += 1
    return repaired


_EVIDENCE_REF_RE = re.compile(r"^\[(?P<sheet>.+?) #(?P<row_id>\d+)\]")


def _redraw_evidence_line(conn, tables, line):
    m = _EVIDENCE_REF_RE.match(line.strip())
    if not m:
        return line
    full = _full_row(conn, tables, m.group("sheet"), int(m.group("row_id")))
    if not full:
        return line
    return " ".join(str(x) for x in (
        m.group(0), full.get("Date and Time"), full.get("Detection Rule"),
        full.get("Event Description")) if x).strip()


def accept_finding(conn, finding_id, status="accepted", with_evidence=True):
    """Pin a finding to the incident timeline.

    The finding becomes one top-level row anchored at its first event (always a real
    float timestamp, so it draws on both timeline charts), and its evidence is pinned
    beneath it as sub-events. Sub-events are collapsed in the table and kept off the
    charts, so attaching them no longer floods the timeline.
    Returns the finding dict, or None if it does not exist / was already decided."""
    row = conn.execute(f"SELECT * FROM {TRIAGE_FINDING_TABLE} WHERE id = ?", (finding_id,)).fetchone()
    if not row:
        return None
    f = finding_to_dict(row)
    if f["status"] in ("accepted", "auto_accepted"):
        return f
    evidence = f["evidence"]
    tables = _sheet_tables(conn)
    span = f"{f['event_count']} event(s), {_fmt_ts(f['first_ts'])} -> {_fmt_ts(f['last_ts'])}"
    note = " ".join(x for x in (f["narrative"], f"[{span}]") if x)
    fields = {
        "Source": "Agentic Triage",
        "Verdict": f["verdict"],
        "Score": str(f["score"]),
        "Severity": f["severity"],
        "MITRE": f["mitre"] or "",
        "Computer Name": f["computer"] or "",
        "Time Range": f"{_fmt_ts(f['first_ts'])} -> {_fmt_ts(f['last_ts'])}",
        "Event Count": str(f["event_count"]),
        "Narrative": f["narrative"] or "",
        "Evidence": "\n".join(
            _evidence_line(conn, tables, e) for e in evidence[:15]),
    }
    parent_id = insert_incident(
        conn, sheet_name="Agentic Triage",
        source_row_id=evidence[0]["row_id"] if evidence else None,
        timestamp=f["first_ts"], date_text=_fmt_ts(f["first_ts"]) if f["first_ts"] is not None else "",
        severity=f["severity"], description=f["title"], computer=f["computer"] or "",
        fields=fields, note=note)
    ids = [parent_id]
    if with_evidence:
        for e in evidence:
            # Pin the real report row (full, untruncated fields incl. raw event log),
            # the same way the manual "pin this row" action does.
            full = _full_row(conn, tables, e["sheet"], e["row_id"])
            fields = dict(full) if full else {
                "Date and Time": e["date"], "Detection Rule": e["rule"],
                "Event Description": e["description"],
            }
            fields["Source"] = "Agentic Triage evidence"
            fields["Finding"] = f["title"]
            ids.append(insert_incident(
                conn, sheet_name=e["sheet"], source_row_id=e["row_id"], timestamp=e["timestamp"],
                date_text=(full or {}).get("Date and Time") or e["date"],
                severity=(full or {}).get("Severity") or f["severity"],
                description=(full or {}).get("Detection Rule")
                            or (full or {}).get("Event Description")
                            or e["rule"] or e["description"],
                computer=(full or {}).get("Computer Name") or f["computer"] or "",
                fields=fields, parent_id=parent_id))
    conn.execute(
        f"UPDATE {TRIAGE_FINDING_TABLE} SET status = ?, decided_at = ?, incident_ids_json = ? WHERE id = ?",
        (status, time.time(), json.dumps(ids), finding_id))
    return f


# ──────────────────────────────────────────────────────────────────────────────
# Runner
# ──────────────────────────────────────────────────────────────────────────────

def _llm_cfg(settings):
    def num(key, default):
        try:
            return int(settings.get(key) or default)
        except (TypeError, ValueError):
            return default
    return {
        "provider": settings["llm_provider"],
        "base_url": settings["llm_base_url"] or None,
        "model": settings["llm_model"],
        "api_key": settings["llm_api_key"] or None,
        "timeout": num("llm_timeout", 200),
        "max_pivots": num("triage_max_pivots", 20),
        "agent_enabled": settings.get("triage_agent_enabled", "1"),
        "agent_rounds": num("triage_agent_rounds", 40),
        "agent_seconds": num("triage_agent_seconds", 900),
        "fast_first_pass": settings.get("triage_fast_first_pass", "1"),
    }


def mark_interrupted_runs(conn):
    """A row still marked 'running' with no live worker can only be left over from
    a killed server. Close it off with its start time so the history is not
    polluted by a run that will never finish. Returns how many were closed."""
    cur = conn.execute(
        f"UPDATE {TRIAGE_RUN_TABLE} SET status = 'interrupted', "
        "finished_at = COALESCE(finished_at, started_at) WHERE status = 'running'")
    return cur.rowcount


def start_run(db_path, scope):
    """Start a background triage run; returns the new run id. Raises RunInProgress."""
    with _lock:
        if _state["status"] == "running":
            raise RunInProgress()
        _cancel.clear()
        conn = sqlite3.connect(db_path)
        try:
            ensure_work_tables(conn)
            mark_interrupted_runs(conn)
            run_id = conn.execute(
                f"INSERT INTO {TRIAGE_RUN_TABLE} (started_at, status, scope_json) VALUES (?,?,?)",
                (time.time(), "running", json.dumps(scope))).lastrowid
            conn.commit()
        finally:
            conn.close()
        _state.update(status="running", run_id=run_id, stage="scope", done=0, total=0,
                      message="Starting", error=None, started_at=time.time(), stats=None)
    settings = settings_store.load_settings()
    threading.Thread(target=_worker, args=(db_path, run_id, scope, settings), daemon=True).start()
    return run_id


def _worker(db_path, run_id, scope, settings):
    from lib import TriageAgent
    status, error, stats, findings = "completed", None, None, []
    try:
        result = TriageAgent.run_triage(
            db_path, scope, _llm_cfg(settings),
            progress_cb=lambda stage, done, total, msg="": _set(stage=stage, done=done, total=total, message=msg),
            cancel_cb=_cancel.is_set)
        findings, stats = result["findings"], result["stats"]
        if result["cancelled"]:
            status = "cancelled"
    except TriageAgent.TriageError as e:
        status, error = "failed", str(e)
    except Exception as e:  # never leave the UI polling a dead run
        status, error = "failed", f"Unexpected error: {e}"

    threshold = None
    override = scope.get("auto_pin_threshold")
    raw = str(override if override not in (None, "") else settings.get("triage_auto_pin_threshold") or "").strip()
    if raw:
        try:
            threshold = int(raw)
        except ValueError:
            threshold = None

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        auto = 0
        for f in findings:
            fid = conn.execute(
                f"INSERT INTO {TRIAGE_FINDING_TABLE} (run_id, cluster_key, title, verdict, score, severity, "
                "mitre, narrative, first_ts, last_ts, computer, event_count, evidence_json, status, "
                "examined_by_agent, tool_trace_json) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,'pending',?,?)",
                (run_id, f["cluster_key"], f["title"], f["verdict"], f["score"], f["severity"], f["mitre"],
                 f["narrative"], f["first_ts"], f["last_ts"], f["computer"], f["event_count"],
                 json.dumps(f["evidence"]), 1 if f.get("from_agent") else 0,
                 json.dumps(f.get("trace") or []))).lastrowid
            if threshold is not None and f["score"] >= threshold:
                accept_finding(conn, fid, status="auto_accepted")
                auto += 1
        if stats is not None:
            stats["findings"], stats["auto_accepted"] = len(findings), auto
        conn.execute(
            f"UPDATE {TRIAGE_RUN_TABLE} SET finished_at = ?, status = ?, stats_json = ?, error = ? WHERE id = ?",
            (time.time(), status, json.dumps(stats or {}), error, run_id))
        conn.commit()
    finally:
        conn.close()
    if status == "completed" and stats is not None and not stats.get("alerts"):
        error = "No alerts matched the scope, so nothing was sent to the LLM."
    elif status == "completed" and stats is not None and stats.get("aborted"):
        # Findings were still produced, so this is a warning rather than a failure.
        error = stats["aborted"]
    _set(status=status, error=error, stats=stats, message=error or status.capitalize())
