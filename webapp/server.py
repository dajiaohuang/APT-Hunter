"""Flask app serving the APT-Hunter web dashboard over a SQLite-cached report."""
import csv
import io
import json
import os
import re
import sqlite3
import time
import xml.dom.minidom as minidom
from datetime import datetime

from flask import Flask, Response, g, jsonify, render_template, request

from . import jobs, settings_store
from .ingest import (
    INCIDENT_TABLE, INCIDENT_TABLE_SQL, RAW_LOG_COLUMN, TRIAGE_FINDING_TABLE, TRIAGE_RUN_TABLE,
    build_db, cache_path_for, ensure_work_tables, needs_rebuild,
)
from .jobs import insert_incident

MAX_PAGE_SIZE = 500
DEFAULT_PAGE_SIZE = 50
MAX_ADVANCED_FILTERS = 10
DISTINCT_VALUES_LIMIT = 500
MAX_CORRELATION_EVENTS = 25

DEFAULT_SETTINGS = settings_store.DEFAULT_SETTINGS

LLM_TEST_EVENT = {
    "datetime": "",
    "message": "Connectivity test",
    "Severity": "Low",
    "Detection Domain": "Test",
    "Event Description": "This is a synthetic event used only to verify the LLM connection.",
    "Event ID": "0",
    "Computer Name": "test-host",
    "Channel": "test",
    "Original Event Log": "",
}


def _load_meta(conn, key):
    row = conn.execute("SELECT value FROM _meta WHERE key = ?", (key,)).fetchone()
    return json.loads(row["value"]) if row else None


def _find_sheet(sheets, name):
    return next((s for s in sheets if s["name"] == name), None)


def _build_where(columns, args):
    clauses = []
    params = []

    q = (args.get("q") or "").strip()
    if q:
        search_cols = [c for c in columns if c != "timestamp"]
        if search_cols:
            ors = " OR ".join(f'"{c}" LIKE ?' for c in search_cols)
            clauses.append(f"({ors})")
            params.extend([f"%{q}%"] * len(search_cols))

    severities = [s for s in args.getlist("severity") if s]
    if severities and "Severity" in columns:
        placeholders = ", ".join("?" for _ in severities)
        clauses.append(f'"Severity" IN ({placeholders})')
        params.extend(severities)

    computer = args.get("computer")
    if computer and "Computer Name" in columns:
        clauses.append('"Computer Name" = ?')
        params.append(computer)

    if "timestamp" in columns:
        start = args.get("start")
        end = args.get("end")
        if start:
            try:
                clauses.append('CAST("timestamp" AS REAL) >= ?')
                params.append(float(start))
            except ValueError:
                pass
        if end:
            try:
                clauses.append('CAST("timestamp" AS REAL) <= ?')
                params.append(float(end))
            except ValueError:
                pass

    raw_filters = args.get("filters")
    if raw_filters:
        try:
            advanced = json.loads(raw_filters)
        except (TypeError, ValueError):
            advanced = []
        if isinstance(advanced, list):
            for clause in advanced[:MAX_ADVANCED_FILTERS]:
                if not isinstance(clause, dict):
                    continue
                col = clause.get("column")
                op = clause.get("op")
                val = clause.get("value", "")
                if col not in columns or val is None or val == "":
                    continue
                if op == "eq":
                    clauses.append(f'"{col}" = ?')
                    params.append(val)
                elif op == "neq":
                    clauses.append(f'("{col}" IS NULL OR "{col}" != ?)')
                    params.append(val)
                elif op == "contains":
                    clauses.append(f'"{col}" LIKE ?')
                    params.append(f"%{val}%")
                elif op == "ncontains":
                    clauses.append(f'("{col}" IS NULL OR "{col}" NOT LIKE ?)')
                    params.append(f"%{val}%")

    where = " AND ".join(clauses) if clauses else "1=1"
    return where, params


def _ensure_incident_table(conn):
    conn.execute(INCIDENT_TABLE_SQL)


def _incident_row_to_dict(row):
    d = dict(row)
    try:
        d["fields"] = json.loads(d.pop("fields_json") or "{}")
    except (TypeError, ValueError):
        d["fields"] = {}
        d.pop("fields_json", None)
    return d


def _child_counts(conn):
    """{parent row id: number of sub-events}."""
    return {r[0]: r[1] for r in conn.execute(
        f"SELECT parent_id, COUNT(*) FROM {INCIDENT_TABLE} "
        "WHERE parent_id IS NOT NULL GROUP BY parent_id")}


def _with_support_counts(conn, rows):
    """Top-level incident dicts for the LLM, each noting how many sub-events back it.

    The sub-events themselves are deliberately left out of the prompt - they stay in
    the timeline table and the CSV export - but the model should know they exist."""
    counts = _child_counts(conn)
    out = []
    for r in rows:
        d = _incident_row_to_dict(r)
        n = counts.get(d["id"], 0)
        if n:
            d["description"] = f"{d.get('description') or ''} ({n} supporting event{'s' if n != 1 else ''})"
        out.append(d)
    return out


def _row_to_llm_event(rowd):
    return {
        "datetime": rowd.get("Date and Time", "N/A"),
        "message": rowd.get("Detection Rule") or rowd.get("Event Description") or "N/A",
        "Severity": rowd.get("Severity", "N/A"),
        "Detection Domain": rowd.get("Detection Domain", "N/A"),
        "Event Description": rowd.get("Event Description", "N/A"),
        "Event ID": rowd.get("Event ID", "N/A"),
        "Computer Name": rowd.get("Computer Name", "N/A"),
        "Channel": rowd.get("Channel", "N/A"),
        "Original Event Log": rowd.get("Original Event Log", "N/A"),
    }


def create_app(report_path, force_rebuild=False):
    db_path = cache_path_for(report_path)
    if force_rebuild or needs_rebuild(report_path, db_path):
        build_db(report_path, db_path)

    # Older builds stored display-shortened text on pinned rows. Put the full
    # text back from the report; restorative, idempotent and a no-op once done.
    _conn = sqlite3.connect(db_path)
    try:
        ensure_work_tables(_conn)
        repaired = jobs.repair_truncated_incidents(_conn)
        linked = jobs.backfill_incident_parents(_conn)
        stale = jobs.mark_interrupted_runs(_conn)
        _conn.commit()
        if repaired:
            print(f"Restored full event text on {repaired} pinned timeline row(s).")
        if linked:
            print(f"Grouped {linked} pinned event(s) under their finding as sub-events.")
        if stale:
            print(f"Marked {stale} unfinished triage run(s) as interrupted.")
    except sqlite3.Error as e:
        print(f"Could not check pinned timeline rows: {e}")
    finally:
        _conn.close()

    app = Flask(__name__)
    app.config["DB_PATH"] = db_path
    app.config["REPORT_PATH"] = report_path

    def get_conn():
        conn = getattr(g, "_db_conn", None)
        if conn is None:
            conn = g._db_conn = sqlite3.connect(app.config["DB_PATH"])
            conn.row_factory = sqlite3.Row
        return conn

    @app.teardown_appcontext
    def _close_conn(_exc):
        conn = getattr(g, "_db_conn", None)
        if conn is not None:
            conn.close()

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/meta")
    def api_meta():
        conn = get_conn()
        sheets = _load_meta(conn, "sheets")
        source = _load_meta(conn, "source")
        dashboard = _load_meta(conn, "dashboard")
        total_events = sum(dashboard["severity_counts"].values())
        return jsonify({
            "report_name": os.path.basename(app.config["REPORT_PATH"]),
            "generated_at": source["built_at"],
            "total_events": total_events,
            "sheets": [
                {k: v for k, v in s.items() if k not in ("table",)}
                for s in sheets
            ],
        })

    @app.route("/api/dashboard")
    def api_dashboard():
        conn = get_conn()
        dashboard = _load_meta(conn, "dashboard")
        sheets = _load_meta(conn, "sheets")

        def top_from_summary(sheet_name, value_col=None, limit=8):
            sheet = _find_sheet(sheets, sheet_name)
            if not sheet:
                return []
            key_col = sheet["columns"][0]
            vcol = value_col or sheet["columns"][1]
            rows = conn.execute(
                f'SELECT "{key_col}" AS k, CAST("{vcol}" AS REAL) AS v FROM "{sheet["table"]}" '
                f'WHERE "{vcol}" IS NOT NULL ORDER BY v DESC LIMIT ?',
                (limit,),
            ).fetchall()
            return [{"label": r["k"], "value": r["v"]} for r in rows]

        timeline = [
            {"date": day, **counts}
            for day, counts in sorted(dashboard["timeline"].items())
        ]
        top_computers = sorted(dashboard["top_computers"].items(), key=lambda kv: -kv[1])[:10]
        top_event_ids = sorted(dashboard["top_event_ids"].items(), key=lambda kv: -kv[1])[:10]

        return jsonify({
            "severity_counts": dashboard["severity_counts"],
            "top_detections": [
                {"label": d[0], "value": d[1]} for d in dashboard["top_detections"][:12]
            ],
            "timeline": timeline,
            "top_computers": [{"label": k, "value": v} for k, v in top_computers],
            "top_event_ids": [{"label": k, "value": v} for k, v in top_event_ids],
            "highlights": {
                "top_processes": top_from_summary("Executed Process Summary"),
                "top_powershell": top_from_summary("Executed Powershell Summary"),
                "top_failed_logins": top_from_summary(
                    "Security Authentication Summary", "Number of Failed Logins"
                ),
                "top_rdp_logons": top_from_summary("Terminal Services Logon Summary"),
            },
        })

    @app.route("/api/sheets/<name>/rows")
    def api_sheet_rows(name):
        conn = get_conn()
        sheets = _load_meta(conn, "sheets")
        sheet = _find_sheet(sheets, name)
        if not sheet:
            return jsonify({"error": "sheet not found"}), 404

        table = sheet["table"]
        columns = sheet["columns"]
        numeric_columns = set(sheet.get("numeric_columns", []))
        display_columns = [c for c in columns if c not in (RAW_LOG_COLUMN, "timestamp")]

        args = request.args
        try:
            page = max(1, int(args.get("page", 1)))
        except ValueError:
            page = 1
        try:
            page_size = min(MAX_PAGE_SIZE, max(10, int(args.get("page_size", DEFAULT_PAGE_SIZE))))
        except ValueError:
            page_size = DEFAULT_PAGE_SIZE

        sort = args.get("sort") or ("timestamp" if "timestamp" in columns else "_id")
        if sort not in columns and sort != "_id":
            sort = "_id"
        direction = "ASC" if (args.get("dir") or "desc").lower() == "asc" else "DESC"
        if sort == "_id":
            order_expr = "_id"
        elif sort in numeric_columns:
            order_expr = f'CAST("{sort}" AS REAL)'
        else:
            order_expr = f'"{sort}"'

        where, params = _build_where(columns, args)

        total = conn.execute(f'SELECT COUNT(*) FROM "{table}" WHERE {where}', params).fetchone()[0]
        offset = (page - 1) * page_size
        sel_cols = ", ".join(f'"{c}"' for c in display_columns)
        query = (
            f'SELECT _id, {sel_cols} FROM "{table}" WHERE {where} '
            f'ORDER BY {order_expr} {direction}, _id DESC LIMIT ? OFFSET ?'
        )
        rows = conn.execute(query, params + [page_size, offset]).fetchall()

        filters = {}
        if "Severity" in columns:
            filters["severity_options"] = [
                r[0] for r in conn.execute(
                    f'SELECT DISTINCT "Severity" FROM "{table}" WHERE "Severity" IS NOT NULL ORDER BY 1'
                ).fetchall()
            ]
        if "Computer Name" in columns:
            filters["computer_options"] = [
                r[0] for r in conn.execute(
                    f'SELECT DISTINCT "Computer Name" FROM "{table}" WHERE "Computer Name" IS NOT NULL ORDER BY 1'
                ).fetchall()
            ]

        return jsonify({
            "columns": display_columns,
            "rows": [dict(r) for r in rows],
            "total": total,
            "page": page,
            "page_size": page_size,
            "has_raw_log": RAW_LOG_COLUMN in columns,
            "filters": filters,
        })

    @app.route("/api/sheets/<name>/distinct")
    def api_sheet_distinct(name):
        conn = get_conn()
        sheets = _load_meta(conn, "sheets")
        sheet = _find_sheet(sheets, name)
        if not sheet:
            return jsonify({"error": "sheet not found"}), 404

        column = request.args.get("column")
        columns = sheet["columns"]
        if not column or column not in columns:
            return jsonify({"error": "unknown column"}), 400

        table = sheet["table"]
        where, params = _build_where(columns, request.args)
        full_where = f'{where} AND "{column}" IS NOT NULL'

        total_distinct = conn.execute(
            f'SELECT COUNT(DISTINCT "{column}") FROM "{table}" WHERE {full_where}', params
        ).fetchone()[0]
        rows = conn.execute(
            f'SELECT "{column}" AS v, COUNT(*) AS c FROM "{table}" WHERE {full_where} '
            f'GROUP BY "{column}" ORDER BY c DESC LIMIT ?',
            params + [DISTINCT_VALUES_LIMIT],
        ).fetchall()

        return jsonify({
            "column": column,
            "total_distinct": total_distinct,
            "values": [{"value": r["v"], "count": r["c"]} for r in rows],
        })

    @app.route("/api/sheets/<name>/row/<int:row_id>")
    def api_sheet_row(name, row_id):
        conn = get_conn()
        sheets = _load_meta(conn, "sheets")
        sheet = _find_sheet(sheets, name)
        if not sheet:
            return jsonify({"error": "sheet not found"}), 404
        row = conn.execute(f'SELECT * FROM "{sheet["table"]}" WHERE _id = ?', (row_id,)).fetchone()
        if not row:
            return jsonify({"error": "row not found"}), 404
        data = dict(row)
        raw = data.get(RAW_LOG_COLUMN)
        if raw and raw.strip().startswith("<"):
            try:
                data[RAW_LOG_COLUMN] = minidom.parseString(raw).toprettyxml(indent="  ")
            except Exception:
                pass
        return jsonify(data)

    @app.route("/api/sheets/<name>/export.csv")
    def api_sheet_export(name):
        conn = get_conn()
        sheets = _load_meta(conn, "sheets")
        sheet = _find_sheet(sheets, name)
        if not sheet:
            return jsonify({"error": "sheet not found"}), 404

        table = sheet["table"]
        columns = sheet["columns"]
        display_columns = [c for c in columns if c not in (RAW_LOG_COLUMN, "timestamp")]
        where, params = _build_where(columns, request.args)
        sel_cols = ", ".join(f'"{c}"' for c in display_columns)
        db_path = app.config["DB_PATH"]

        def generate():
            # Uses its own connection: this generator keeps yielding after the
            # request-scoped connection in `g` has already been torn down.
            export_conn = sqlite3.connect(db_path)
            try:
                buf = io.StringIO()
                writer = csv.writer(buf)
                writer.writerow(display_columns)
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate(0)
                cur = export_conn.execute(f'SELECT {sel_cols} FROM "{table}" WHERE {where}', params)
                while True:
                    batch = cur.fetchmany(1000)
                    if not batch:
                        break
                    for r in batch:
                        writer.writerow(r)
                    yield buf.getvalue()
                    buf.seek(0)
                    buf.truncate(0)
            finally:
                export_conn.close()

        filename = re.sub(r'[^0-9a-zA-Z_.-]', '_', name) + ".csv"
        return Response(
            generate(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    @app.route("/api/incidents", methods=["GET"])
    def api_incidents_list():
        conn = get_conn()
        _ensure_incident_table(conn)
        rows = conn.execute(
            f"SELECT * FROM {INCIDENT_TABLE} ORDER BY timestamp ASC, id ASC"
        ).fetchall()
        counts = _child_counts(conn)
        out = []
        for r in rows:
            d = _incident_row_to_dict(r)
            d["child_count"] = counts.get(d["id"], 0)
            out.append(d)
        return jsonify(out)

    @app.route("/api/incidents", methods=["POST"])
    def api_incidents_add():
        data = request.get_json(silent=True) or {}
        sheet_name = data.get("sheet_name")
        row_id = data.get("row_id")

        if sheet_name and row_id is not None:
            # Pin an existing report row.
            conn = get_conn()
            sheets = _load_meta(conn, "sheets")
            sheet = _find_sheet(sheets, sheet_name)
            if not sheet:
                return jsonify({"error": "sheet not found"}), 404

            row = conn.execute(f'SELECT * FROM "{sheet["table"]}" WHERE _id = ?', (row_id,)).fetchone()
            if not row:
                return jsonify({"error": "row not found"}), 404
            rowd = dict(row)

            timestamp = None
            if rowd.get("timestamp"):
                try:
                    timestamp = float(rowd["timestamp"])
                except (TypeError, ValueError):
                    timestamp = None
            date_text = rowd.get("Date and Time") or ""
            severity = rowd.get("Severity") or ""
            description = rowd.get("Detection Rule") or rowd.get("Event Description") or sheet_name
            computer = rowd.get("Computer Name") or ""
            fields = rowd
            note = data.get("note", "")
        else:
            # Analyst-authored finding, not tied to any report row.
            description = (data.get("description") or "").strip()
            if not description:
                return jsonify({"error": "description is required"}), 400
            sheet_name = "Manual Entry"
            row_id = None
            severity = data.get("severity") or "Informational"
            computer = data.get("computer") or ""
            note = data.get("note", "")
            timestamp = None
            if data.get("timestamp") is not None:
                try:
                    timestamp = float(data["timestamp"])
                except (TypeError, ValueError):
                    timestamp = None
            date_text = data.get("date_text") or ""
            fields = {
                "Source": "Manual Entry",
                "Date and Time": date_text,
                "Severity": severity,
                "Computer Name": computer,
                "Description": description,
            }
            conn = get_conn()

        _ensure_incident_table(conn)
        new_id = insert_incident(
            conn, sheet_name=sheet_name, source_row_id=row_id, timestamp=timestamp,
            date_text=date_text, severity=severity, description=description,
            computer=computer, fields=fields, note=note)
        conn.commit()
        created = conn.execute(
            f"SELECT * FROM {INCIDENT_TABLE} WHERE id = ?", (new_id,)
        ).fetchone()
        return jsonify(_incident_row_to_dict(created)), 201

    @app.route("/api/incidents/<int:incident_id>", methods=["PATCH"])
    def api_incidents_update(incident_id):
        data = request.get_json(silent=True) or {}
        conn = get_conn()
        _ensure_incident_table(conn)
        conn.execute(
            f"UPDATE {INCIDENT_TABLE} SET note = ? WHERE id = ?",
            (data.get("note", ""), incident_id),
        )
        conn.commit()
        row = conn.execute(f"SELECT * FROM {INCIDENT_TABLE} WHERE id = ?", (incident_id,)).fetchone()
        if not row:
            return jsonify({"error": "incident not found"}), 404
        return jsonify(_incident_row_to_dict(row))

    @app.route("/api/incidents/<int:incident_id>", methods=["DELETE"])
    def api_incidents_delete(incident_id):
        conn = get_conn()
        _ensure_incident_table(conn)
        ensure_work_tables(conn)
        result = jobs.delete_incidents(conn, [incident_id])
        conn.commit()
        return jsonify({"ok": True, **result})

    MAX_BULK_DELETE = 5000

    @app.route("/api/incidents/bulk-delete", methods=["POST"])
    def api_incidents_bulk_delete():
        data = request.get_json(silent=True) or {}
        raw = data.get("ids")
        if not isinstance(raw, list) or not raw:
            return jsonify({"error": "ids (a non-empty list) is required"}), 400
        if len(raw) > MAX_BULK_DELETE:
            return jsonify({"error": f"Too many events selected (max {MAX_BULK_DELETE})"}), 400
        try:
            ids = [int(x) for x in raw]
        except (TypeError, ValueError):
            return jsonify({"error": "ids must be a list of integers"}), 400
        conn = get_conn()
        _ensure_incident_table(conn)
        ensure_work_tables(conn)
        result = jobs.delete_incidents(conn, ids)
        conn.commit()
        return jsonify({"ok": True, **result})

    @app.route("/api/incidents/report", methods=["POST"])
    def api_incidents_report():
        data = request.get_json(silent=True) or {}
        title = (data.get("title") or "Incident Response Report").strip()
        prepared_by = (data.get("prepared_by") or "").strip()

        conn = get_conn()
        _ensure_incident_table(conn)
        rows = conn.execute(
            f"SELECT * FROM {INCIDENT_TABLE} WHERE parent_id IS NULL "
            "ORDER BY timestamp ASC, id ASC"
        ).fetchall()
        if not rows:
            return jsonify({"error": "No events are pinned to the incident timeline yet."}), 400
        incidents = _with_support_counts(conn, rows)

        settings = settings_store.load_settings()
        from lib import LLMAnalyzer
        try:
            timeout = int(settings.get("llm_timeout") or 200)
        except (TypeError, ValueError):
            timeout = 200
        result = LLMAnalyzer.generate_incident_report(
            incidents,
            title=title,
            prepared_by=prepared_by,
            llm_provider=settings["llm_provider"],
            llm_base_url=settings["llm_base_url"] or None,
            llm_model=settings["llm_model"],
            llm_api_key=settings["llm_api_key"] or None,
            timeout=timeout,
        )
        if result.get("error"):
            return jsonify(result)
        return jsonify({"content": result["content"], "title": title, "prepared_by": prepared_by})

    @app.route("/api/incidents/summary", methods=["POST"])
    def api_incidents_summary():
        data = request.get_json(silent=True) or {}
        organization = (data.get("organization") or "").strip()

        conn = get_conn()
        _ensure_incident_table(conn)
        rows = conn.execute(
            f"SELECT * FROM {INCIDENT_TABLE} WHERE parent_id IS NULL "
            "ORDER BY timestamp ASC, id ASC"
        ).fetchall()
        if not rows:
            return jsonify({"error": "No events are pinned to the incident timeline yet."}), 400
        incidents = _with_support_counts(conn, rows)

        settings = settings_store.load_settings()
        from lib import LLMAnalyzer
        try:
            timeout = int(settings.get("llm_timeout") or 200)
        except (TypeError, ValueError):
            timeout = 200
        result = LLMAnalyzer.generate_executive_summary(
            incidents,
            organization=organization,
            llm_provider=settings["llm_provider"],
            llm_base_url=settings["llm_base_url"] or None,
            llm_model=settings["llm_model"],
            llm_api_key=settings["llm_api_key"] or None,
            timeout=timeout,
        )
        if result.get("error"):
            return jsonify(result)
        return jsonify({"content": result["content"], "organization": organization})

    @app.route("/api/incidents/report/docx", methods=["POST"])
    def api_incidents_report_docx():
        data = request.get_json(silent=True) or {}
        title = (data.get("title") or "Incident Response Report").strip()
        prepared_by = (data.get("prepared_by") or "").strip()
        content = (data.get("content") or "").strip()
        if not content:
            return jsonify({"error": "No report content to export."}), 400

        from .doc_export import markdown_to_docx_bytes
        subtitle_parts = []
        if prepared_by:
            subtitle_parts.append(f"Prepared by {prepared_by}")
        subtitle_parts.append(datetime.now().strftime("%Y-%m-%d %H:%M"))
        subtitle = " • ".join(subtitle_parts)

        buf = markdown_to_docx_bytes(content, title=title, subtitle=subtitle)
        filename = re.sub(r'[^0-9a-zA-Z_.-]', '_', title) + ".docx"
        return Response(
            buf.getvalue(),
            mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    @app.route("/api/settings", methods=["GET"])
    def api_settings_get():
        return jsonify(settings_store.load_settings())

    @app.route("/api/settings", methods=["POST"])
    def api_settings_post():
        data = request.get_json(silent=True) or {}
        return jsonify(settings_store.save_settings(data))

    @app.route("/api/settings/test", methods=["POST"])
    def api_settings_test():
        data = request.get_json(silent=True) or {}
        settings = dict(settings_store.load_settings())
        for key in DEFAULT_SETTINGS:
            if data.get(key):
                settings[key] = data[key]

        from lib import LLMAnalyzer
        try:
            timeout = int(settings.get("llm_timeout") or 200)
        except (TypeError, ValueError):
            timeout = 200
        result = LLMAnalyzer.analyze_single_event(
            LLM_TEST_EVENT,
            llm_provider=settings["llm_provider"],
            llm_base_url=settings["llm_base_url"] or None,
            llm_model=settings["llm_model"],
            llm_api_key=settings["llm_api_key"] or None,
            timeout=timeout,
        )
        if result.get("is_error"):
            return jsonify({"ok": False, "message": result.get("reason", "Unknown error")})
        return jsonify({
            "ok": True,
            "message": f"Connected — model responded (score={result.get('score')}, malicious={result.get('is_malicious')}).",
        })

    @app.route("/api/sheets/<name>/row/<int:row_id>/llm-check", methods=["POST"])
    def api_llm_check(name, row_id):
        conn = get_conn()
        sheets = _load_meta(conn, "sheets")
        sheet = _find_sheet(sheets, name)
        if not sheet:
            return jsonify({"error": "sheet not found"}), 404
        row = conn.execute(f'SELECT * FROM "{sheet["table"]}" WHERE _id = ?', (row_id,)).fetchone()
        if not row:
            return jsonify({"error": "row not found"}), 404

        settings = settings_store.load_settings()
        from lib import LLMAnalyzer
        try:
            timeout = int(settings.get("llm_timeout") or 200)
        except (TypeError, ValueError):
            timeout = 200
        result = LLMAnalyzer.analyze_single_event(
            _row_to_llm_event(dict(row)),
            llm_provider=settings["llm_provider"],
            llm_base_url=settings["llm_base_url"] or None,
            llm_model=settings["llm_model"],
            llm_api_key=settings["llm_api_key"] or None,
            timeout=timeout,
        )
        return jsonify(result)

    @app.route("/api/sheets/<name>/row/<int:row_id>/llm-explain", methods=["POST"])
    def api_llm_explain(name, row_id):
        conn = get_conn()
        sheets = _load_meta(conn, "sheets")
        sheet = _find_sheet(sheets, name)
        if not sheet:
            return jsonify({"error": "sheet not found"}), 404
        row = conn.execute(f'SELECT * FROM "{sheet["table"]}" WHERE _id = ?', (row_id,)).fetchone()
        if not row:
            return jsonify({"error": "row not found"}), 404

        settings = settings_store.load_settings()
        from lib import LLMAnalyzer
        try:
            timeout = int(settings.get("llm_timeout") or 200)
        except (TypeError, ValueError):
            timeout = 200
        result = LLMAnalyzer.explain_event(
            _row_to_llm_event(dict(row)),
            llm_provider=settings["llm_provider"],
            llm_base_url=settings["llm_base_url"] or None,
            llm_model=settings["llm_model"],
            llm_api_key=settings["llm_api_key"] or None,
            timeout=timeout,
        )
        return jsonify(result)

    @app.route("/api/sheets/<name>/llm-correlate", methods=["POST"])
    def api_llm_correlate(name):
        data = request.get_json(silent=True) or {}
        raw_ids = data.get("row_ids")
        if not isinstance(raw_ids, list) or not raw_ids:
            return jsonify({"error": "row_ids (a non-empty list) is required"}), 400
        if len(raw_ids) > MAX_CORRELATION_EVENTS:
            return jsonify({"error": f"Too many events selected (max {MAX_CORRELATION_EVENTS})"}), 400
        try:
            row_ids = [int(x) for x in raw_ids]
        except (TypeError, ValueError):
            return jsonify({"error": "row_ids must be a list of integers"}), 400

        conn = get_conn()
        sheets = _load_meta(conn, "sheets")
        sheet = _find_sheet(sheets, name)
        if not sheet:
            return jsonify({"error": "sheet not found"}), 404

        table = sheet["table"]
        columns = sheet["columns"]
        placeholders = ", ".join("?" for _ in row_ids)
        order_clause = ' ORDER BY CAST("timestamp" AS REAL) ASC' if "timestamp" in columns else ""
        rows = conn.execute(
            f'SELECT * FROM "{table}" WHERE _id IN ({placeholders}){order_clause}', row_ids
        ).fetchall()
        if not rows:
            return jsonify({"error": "no matching rows found"}), 404

        row_dicts = [dict(r) for r in rows]
        events = [_row_to_llm_event(r) for r in row_dicts]

        settings = settings_store.load_settings()
        from lib import LLMAnalyzer
        try:
            timeout = int(settings.get("llm_timeout") or 200)
        except (TypeError, ValueError):
            timeout = 200
        result = LLMAnalyzer.analyze_event_correlation(
            events,
            llm_provider=settings["llm_provider"],
            llm_base_url=settings["llm_base_url"] or None,
            llm_model=settings["llm_model"],
            llm_api_key=settings["llm_api_key"] or None,
            timeout=timeout,
        )
        if result.get("error"):
            return jsonify(result)

        display_columns = [c for c in columns if c not in (RAW_LOG_COLUMN, "timestamp")]
        related_indices = set(result.get("related_event_numbers", []))
        related_rows = [
            {k: v for k, v in r.items() if k in display_columns or k == "_id"}
            for i, r in enumerate(row_dicts, start=1)
            if i in related_indices
        ]

        return jsonify({
            "correlated": result.get("correlated", False),
            "narrative": result.get("narrative", ""),
            "confidence": result.get("confidence", 0),
            "columns": display_columns,
            "rows": related_rows,
            "total_selected": len(row_dicts),
            "total_related": len(related_rows),
        })

    # ---------------- Agentic triage ----------------

    def _triage_scope(data):
        computers = data.get("computers") or []
        if not isinstance(computers, list):
            computers = []
        scope = {
            "severity_min": data.get("severity_min") or "",
            "computers": [str(c) for c in computers if c],
            "start": data.get("start"),
            "end": data.get("end"),
        }
        if data.get("auto_pin_threshold") not in (None, ""):
            scope["auto_pin_threshold"] = data["auto_pin_threshold"]
        return scope

    @app.route("/api/triage/run", methods=["POST"])
    def api_triage_run():
        data = request.get_json(silent=True) or {}
        scope = _triage_scope(data)
        if scope["severity_min"] and scope["severity_min"].capitalize() not in (
                "Informational", "Low", "Medium", "High", "Critical"):
            return jsonify({"error": "invalid severity_min"}), 400
        from lib import TriageAgent
        preview = TriageAgent.scope_preview(app.config["DB_PATH"], scope)
        if preview["matched"] == 0:
            span = ""
            if preview["first_ts"] is not None:
                fmt = lambda t: datetime.utcfromtimestamp(t).strftime("%Y-%m-%d %H:%M UTC")
                span = f" This report's alerts span {fmt(preview['first_ts'])} to {fmt(preview['last_ts'])}."
            return jsonify({"error": "No alerts match this scope, so there is nothing to triage." + span
                            + " Widen the severity, computer or time filters."}), 400
        try:
            run_id = jobs.start_run(app.config["DB_PATH"], scope)
        except jobs.RunInProgress:
            return jsonify({"error": "A triage run is already in progress."}), 409
        return jsonify({"run_id": run_id}), 202

    @app.route("/api/triage/scope", methods=["GET"])
    def api_triage_scope():
        from lib import TriageAgent
        return jsonify(TriageAgent.scope_preview(app.config["DB_PATH"], {}))

    @app.route("/api/triage/status", methods=["GET"])
    def api_triage_status():
        return jsonify(jobs.get_status())

    @app.route("/api/triage/cancel", methods=["POST"])
    def api_triage_cancel():
        return jsonify({"cancelling": jobs.cancel()})

    def _run_to_dict(row, counts):
        d = dict(row)
        for key in ("scope_json", "stats_json"):
            try:
                d[key[:-5]] = json.loads(d.pop(key) or "{}")
            except (TypeError, ValueError):
                d[key[:-5]] = {}
                d.pop(key, None)
        started, finished = d.get("started_at"), d.get("finished_at")
        # A finished run's duration is fixed; a live one is measured against now,
        # so the UI can tick without needing its own start reference.
        d["duration"] = round((finished or time.time()) - started, 1) if started else None
        d["running"] = d.get("status") == "running"
        by_status = counts.get(d["id"], {})
        d["finding_counts"] = by_status
        d["finding_total"] = sum(by_status.values())
        return d

    @app.route("/api/triage/runs", methods=["GET"])
    def api_triage_runs():
        conn = get_conn()
        ensure_work_tables(conn)
        limit = min(request.args.get("limit", default=25, type=int) or 25, 200)
        rows = conn.execute(
            f"SELECT * FROM {TRIAGE_RUN_TABLE} ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        counts = {}
        for r in conn.execute(
                f"SELECT run_id, status, COUNT(*) c FROM {TRIAGE_FINDING_TABLE} GROUP BY run_id, status"):
            counts.setdefault(r["run_id"], {})[r["status"]] = r["c"]
        return jsonify({"runs": [_run_to_dict(r, counts) for r in rows]})

    @app.route("/api/triage/findings", methods=["GET"])
    def api_triage_findings():
        conn = get_conn()
        ensure_work_tables(conn)
        run_id = request.args.get("run_id", type=int)
        if run_id is None:
            row = conn.execute(f"SELECT MAX(id) FROM {TRIAGE_RUN_TABLE}").fetchone()
            run_id = row[0]
        if run_id is None:
            return jsonify({"run": None, "findings": []})
        run = conn.execute(f"SELECT * FROM {TRIAGE_RUN_TABLE} WHERE id = ?", (run_id,)).fetchone()
        rows = conn.execute(
            f"SELECT * FROM {TRIAGE_FINDING_TABLE} WHERE run_id = ? ORDER BY score DESC, id ASC", (run_id,)
        ).fetchall()
        counts = {}
        for r in conn.execute(
                f"SELECT run_id, status, COUNT(*) c FROM {TRIAGE_FINDING_TABLE} "
                "WHERE run_id = ? GROUP BY run_id, status", (run_id,)):
            counts.setdefault(r["run_id"], {})[r["status"]] = r["c"]
        return jsonify({"run": _run_to_dict(run, counts) if run else None,
                        "findings": [jobs.finding_to_dict(r) for r in rows]})

    def _decide(finding_id, accept):
        conn = get_conn()
        ensure_work_tables(conn)
        if accept:
            # Accepting always attaches the evidence as sub-events; they are collapsed
            # in the table and kept off the charts, so there is nothing to opt out of.
            f = jobs.accept_finding(conn, finding_id)
        else:
            cur = conn.execute(
                f"UPDATE {TRIAGE_FINDING_TABLE} SET status = 'rejected', decided_at = ? "
                "WHERE id = ? AND status = 'pending'", (time.time(), finding_id))
            f = True if cur.rowcount else None
        if f is None:
            return jsonify({"error": "finding not found"}), 404
        conn.commit()
        row = conn.execute(f"SELECT * FROM {TRIAGE_FINDING_TABLE} WHERE id = ?", (finding_id,)).fetchone()
        return jsonify(jobs.finding_to_dict(row))

    @app.route("/api/triage/findings/<int:finding_id>/accept", methods=["POST"])
    def api_triage_accept(finding_id):
        return _decide(finding_id, True)

    @app.route("/api/triage/findings/<int:finding_id>/reject", methods=["POST"])
    def api_triage_reject(finding_id):
        return _decide(finding_id, False)

    @app.route("/api/triage/findings/accept-all", methods=["POST"])
    def api_triage_accept_all():
        conn = get_conn()
        ensure_work_tables(conn)
        ids = [r[0] for r in conn.execute(
            f"SELECT id FROM {TRIAGE_FINDING_TABLE} WHERE status = 'pending' ORDER BY score DESC").fetchall()]
        for fid in ids:
            jobs.accept_finding(conn, fid)
        conn.commit()
        return jsonify({"accepted": len(ids)})

    return app
