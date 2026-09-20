"""
LLMAnalyzer.py  –  APT-Hunter Local LLM Analysis Module
=========================================================
Sends each APT-Hunter detected event individually to a local LLM
(via an OpenAI-compatible REST API such as Ollama or LM Studio) and asks:
  1. Is this event malicious? (yes / no)
  2. Maliciousness score 0-100

Usage (called internally by APT-Hunter.py):
    from lib import LLMAnalyzer
    results = LLMAnalyzer.analyze_events_with_llm(
        events_df     = allresults_df,
        min_severity  = "High",
        llm_base_url  = "http://localhost:11434/v1",
        llm_model     = "llama3",
    )
"""

import json
import re
import textwrap
import traceback
import logging
import time
from typing import Optional

import pandas as pd

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

SEVERITY_ORDER = ["Informational", "Low", "Medium", "High", "Critical"]

# ── Context-aware batching ──────────────────────────────────────────────────
# Fraction of the model's context window that batches are allowed to fill.
# The remainder is headroom for the response and estimation error.
CONTEXT_USAGE_RATIO = 0.8

# Rough chars-per-token heuristic used to size batches without pulling in a
# model-specific tokenizer dependency. ~4 chars/token is the standard
# approximation for English text.
CHARS_PER_TOKEN = 4

# Rough token allowance reserved per event for its JSON response in a batch.
EST_OUTPUT_TOKENS_PER_EVENT = 60

# Used when the model's context window can't be determined or supplied.
DEFAULT_CONTEXT_SIZE = 8192

# Columns fed to the LLM for each event
LLM_EVENT_COLUMNS = [
    "datetime",
    "message",           # Detection rule name
    "Severity",
    "Detection Domain",
    "Event Description",
    "Event ID",
    "Computer Name",
    "Channel",
    "Original Event Log",
]

SYSTEM_PROMPT = textwrap.dedent("""\
    You are an expert cybersecurity threat analyst specialising in Windows event log forensics.
    You will be given a single Windows security event detected by APT-Hunter.

    Your ONLY task is to evaluate whether this event is malicious and assign a maliciousness score.

    You MUST reply with valid JSON only — no additional text, no markdown fences, no explanation outside the JSON.

    JSON schema:
    {
      "is_malicious": true | false,
      "score": <integer 0-100>,
      "reason": "<one concise sentence explaining the score>"
    }

    Scoring guide:
      0  – Completely benign, expected system behaviour
      1-19  – Very low risk, unlikely malicious
      20-39 – Low risk, minor concern
      40-59 – Moderate risk, warrants investigation
      60-79 – High risk, likely malicious
      80-99 – Very high risk, strong indicators of compromise
      100 – Certain malicious activity / confirmed attack

    Set is_malicious to true when score >= 60.
""")

CORRELATION_SYSTEM_PROMPT = textwrap.dedent("""\
    You are an expert cybersecurity threat analyst specialising in Windows event log forensics and
    attack-chain reconstruction. You will be given multiple Windows security events (each labelled
    EVENT #N), hand-picked by an analyst who wants to know whether any of them are related.

    Your task:
      1. Decide whether any of these events appear related to each other (e.g. part of the same
         attack chain, campaign, lateral movement sequence, or a single actor's activity).
      2. Identify exactly which events (by number) belong to that related set. Leave out events
         that are unrelated noise, even if most of the batch turns out to be related.
      3. Explain the relationship / narrative connecting them, ideally in chronological order.

    You MUST reply with valid JSON only — no additional text, no markdown fences.

    JSON schema:
    {
      "correlated": true | false,
      "related_event_numbers": [1, 3, 4],
      "narrative": "<a few sentences connecting the related events, or explaining why none relate>",
      "confidence": <integer 0-100>
    }

    If none of the events appear related, set correlated to false and related_event_numbers to [].
""")

EXPLAIN_SYSTEM_PROMPT = textwrap.dedent("""\
    You are an expert cybersecurity threat analyst specialising in Windows event log forensics.
    You will be given a single Windows security event detected by APT-Hunter.

    Explain this event in plain language for a security analyst, covering:
      - What happened and what likely triggered this detection
      - Why it might matter from a security perspective (or why it is likely benign)
      - Relevant MITRE ATT&CK technique(s) if applicable
      - Suggested next investigative steps

    Reply in clear, concise prose (a few short paragraphs at most). Do not reply with JSON.
""")

BATCH_SYSTEM_PROMPT = textwrap.dedent("""\
    You are an expert cybersecurity threat analyst specialising in Windows event log forensics.
    You will be given one or more Windows security events (each labelled EVENT #N) detected by APT-Hunter.

    Your ONLY task is to evaluate whether each event is malicious and assign a maliciousness score.

    You MUST reply with a valid JSON array only — one object per event, in the same order given.
    No additional text, no markdown fences, no explanation outside the JSON.

    JSON schema (array with one object per event):
    [
      {
        "is_malicious": true | false,
        "score": <integer 0-100>,
        "reason": "<one concise sentence explaining the score>"
      }
    ]

    Scoring guide:
      0     – Completely benign, expected system behaviour
      1-19  – Very low risk, unlikely malicious
      20-39 – Low risk, minor concern
      40-59 – Moderate risk, warrants investigation
      60-79 – High risk, likely malicious
      80-99 – Very high risk, strong indicators of compromise
      100   – Certain malicious activity / confirmed attack

    Set is_malicious to true when score >= 60.
""")


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _severity_rank(sev: str) -> int:
    """Return a numeric rank for a severity string (higher = more severe)."""
    try:
        return SEVERITY_ORDER.index(str(sev).strip().capitalize())
    except ValueError:
        return -1


def _filter_by_severity(df: pd.DataFrame, min_severity: str) -> pd.DataFrame:
    """Return rows whose Severity is >= min_severity."""
    min_rank = _severity_rank(min_severity)
    mask = df["Severity"].apply(lambda s: _severity_rank(s) >= min_rank)
    return df[mask].copy()


def _build_event_message(row: pd.Series) -> str:
    """Render a single event row as a readable text block for the LLM."""
    lines = ["Windows Security Event Details:"]
    for col in LLM_EVENT_COLUMNS:
        val = row.get(col, "N/A")
        if pd.isna(val) or str(val).strip() == "":
            val = "N/A"
        lines.append(f"  {col}: {val}")
    return "\n".join(lines)


def _build_batch_message(rows: list) -> str:
    """Render multiple event rows as numbered blocks for a single batch LLM call."""
    parts = []
    for i, row in enumerate(rows, start=1):
        parts.append(f"--- EVENT #{i} ---")
        parts.append(_build_event_message(row))
    return "\n\n".join(parts)


def _parse_llm_json(raw: str) -> dict:
    """
    Extract and parse the JSON object from the LLM's response.
    Handles cases where the model wraps output in markdown fences.
    Returns a dict with keys: is_malicious, score, reason.
    """
    # Strip markdown code fences if present
    clean = re.sub(r"```(?:json)?", "", raw, flags=re.IGNORECASE).strip("` \n")

    # Extract the first {...} block
    match = re.search(r"\{.*?\}", clean, re.DOTALL)
    if match:
        try:
            data = json.loads(match.group())
            return {
                "is_error":     bool(data.get("is_error", False)),
                "is_malicious": bool(data.get("is_malicious", False)),
                "score":        int(data.get("score", 0)),
                "reason":       str(data.get("reason", "")).strip(),
            }
        except (json.JSONDecodeError, ValueError):
            pass

    # Fallback: try to extract score with regex
    score_match = re.search(r'"?score"?\s*:\s*(\d+)', raw)
    score = int(score_match.group(1)) if score_match else 0
    malicious = score >= 60
    return {
        "is_error":     False,   # Assume regex match means we at least got a score, even if format is weird
        "is_malicious": malicious,
        "score":        score,
        "reason":       f"[Parse error – raw response]: {raw[:200]}",
    }


def _parse_llm_json_batch(raw: str, expected: int) -> list:
    """
    Extract and parse a JSON array from the LLM's batch response.
    Returns a list of exactly *expected* dicts with keys: is_error, is_malicious, score, reason.
    """
    clean = re.sub(r"```(?:json)?", "", raw, flags=re.IGNORECASE).strip("` \n")

    match = re.search(r"\[.*\]", clean, re.DOTALL)
    if match:
        try:
            data = json.loads(match.group())
            if isinstance(data, list):
                parsed = []
                for item in data:
                    parsed.append({
                        "is_error":     bool(item.get("is_error", False)),
                        "is_malicious": bool(item.get("is_malicious", False)),
                        "score":        int(item.get("score", 0)),
                        "reason":       str(item.get("reason", "")).strip(),
                    })
                # Pad if LLM returned fewer results than expected
                while len(parsed) < expected:
                    parsed.append({
                        "is_error":     True,
                        "is_malicious": False,
                        "score":        -1,
                        "reason":       "[ERROR] LLM returned fewer results than expected in batch.",
                    })
                return parsed[:expected]
        except (json.JSONDecodeError, ValueError):
            pass

    # Fallback: parse as single object and broadcast to all events in the batch
    single = _parse_llm_json(raw)
    return [single] * expected


def _estimate_tokens(text: str) -> int:
    """Rough token count estimate for *text* (see CHARS_PER_TOKEN)."""
    return max(1, len(text) // CHARS_PER_TOKEN)


def _detect_model_context_size(base_url: str, model: str) -> Optional[int]:
    """
    Best-effort auto-detection of a model's context window (in tokens).

    Currently only Ollama's native /api/show endpoint exposes this. Returns
    None (unknown) for any other provider or on any failure, in which case
    the caller falls back to a fixed/default batch size.
    """
    try:
        import requests
    except ImportError:
        return None

    # The OpenAI-compatible base URL is typically ".../v1"; Ollama's native
    # /api/show endpoint lives one level up from there.
    native_base = re.sub(r"/v1/?$", "", base_url.rstrip("/"))
    url = native_base + "/api/show"
    try:
        response = requests.post(url, json={"model": model}, timeout=10)
        response.raise_for_status()
        model_info = response.json().get("model_info", {})
        for key, value in model_info.items():
            if key.endswith(".context_length") and isinstance(value, int) and value > 0:
                return value
    except Exception:
        pass
    return None


def _pack_batches_to_context(
    rows: list,
    system_prompt: str,
    context_size: int,
    max_batch_size: int,
    usage_ratio: float = CONTEXT_USAGE_RATIO,
) -> list:
    """
    Greedily group *rows* into batches so each batch's estimated prompt +
    response token usage stays within `usage_ratio` (default 80%) of
    *context_size*, additionally capped at *max_batch_size* events/request.
    """
    budget = int(context_size * usage_ratio)
    system_tokens = _estimate_tokens(system_prompt)
    available = max(budget - system_tokens, EST_OUTPUT_TOKENS_PER_EVENT + 100)

    batches = []
    current_batch: list = []
    current_tokens = 0

    for row in rows:
        event_tokens = _estimate_tokens(_build_event_message(row)) + EST_OUTPUT_TOKENS_PER_EVENT
        exceeds_context = current_batch and (current_tokens + event_tokens > available)
        exceeds_cap = len(current_batch) >= max_batch_size
        if current_batch and (exceeds_context or exceeds_cap):
            batches.append(current_batch)
            current_batch = []
            current_tokens = 0
        current_batch.append(row)
        current_tokens += event_tokens

    if current_batch:
        batches.append(current_batch)
    return batches


def _resolve_provider(llm_provider: str, llm_base_url: Optional[str], llm_api_key: Optional[str]) -> tuple:
    """Map a provider name to its default base URL / API key when not explicitly given."""
    prov = str(llm_provider).lower().strip()
    if prov in ["llmstudio", "lmstudio"]:
        base_url = llm_base_url or "http://localhost:1234/v1"
        api_key = llm_api_key or "lm-studio"
    elif prov == "llama.cpp":
        base_url = llm_base_url or "http://localhost:8080/v1"
        api_key = llm_api_key or "llama.cpp"
    else:  # default to ollama
        base_url = llm_base_url or "http://localhost:11434/v1"
        api_key = llm_api_key or "ollama"
    return base_url, api_key


def _extract_error_reason(raw: str) -> Optional[str]:
    """If the LLM call itself failed, _call_llm encodes it as a small JSON error
    payload. Returns the reason string if this is such a payload, else None."""
    try:
        clean = re.sub(r"```(?:json)?", "", raw, flags=re.IGNORECASE).strip("` \n")
        match = re.search(r"\{.*?\}", clean, re.DOTALL)
        if match:
            data = json.loads(match.group())
            if data.get("is_error"):
                return str(data.get("reason", "Unknown LLM error"))
    except (json.JSONDecodeError, ValueError, TypeError):
        pass
    return None


_ZERO_USAGE = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}


def _call_llm(
    base_url: str,
    model: str,
    api_key: str,
    messages: list,
    timeout: int = 200,
) -> tuple:
    """
    POST a chat-completion request to an OpenAI-compatible local LLM.
    Returns (content_str, usage_dict) where usage_dict has prompt_tokens,
    completion_tokens, and total_tokens (all 0 when unavailable or on error).
    """
    try:
        import requests
    except ImportError:
        return '{"is_malicious": false, "score": 0, "reason": "[ERROR] requests library not installed."}', _ZERO_USAGE

    url = base_url.rstrip("/") + "/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    payload = {
        "model":       model,
        "messages":    messages,
        "temperature": 0.1,   # very low = consistent, deterministic scoring
        "stream":      False,
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=timeout)
        response.raise_for_status()
        data = response.json()
        raw_usage = data.get("usage", {})
        usage = {
            "prompt_tokens":     raw_usage.get("prompt_tokens", 0),
            "completion_tokens": raw_usage.get("completion_tokens", 0),
            "total_tokens":      raw_usage.get("total_tokens", 0),
        }
        return data["choices"][0]["message"]["content"], usage
    except requests.exceptions.ConnectionError:
        return (
            f'{{"is_error": true, "is_malicious": false, "score": -1, "reason": "[ERROR] Cannot connect to LLM at {url}. '
            f'Ensure your LLM server is running (e.g. ollama serve)."}}'
        ), _ZERO_USAGE
    except requests.exceptions.Timeout:
        return f'{{"is_error": true, "is_malicious": false, "score": -1, "reason": "[ERROR] LLM request timed out after {timeout}s."}}', _ZERO_USAGE
    except requests.exceptions.HTTPError as e:
        return f'{{"is_error": true, "is_malicious": false, "score": -1, "reason": "[ERROR] HTTP {e}"}}', _ZERO_USAGE
    except (KeyError, json.JSONDecodeError) as e:
        return f'{{"is_error": true, "is_malicious": false, "score": -1, "reason": "[ERROR] Unexpected LLM response format: {e}"}}', _ZERO_USAGE
    except Exception as e:
        logging.error(traceback.format_exc())
        return f'{{"is_error": true, "is_malicious": false, "score": -1, "reason": "[ERROR] {e}"}}', _ZERO_USAGE


def call_llm_tools(
    base_url: str,
    model: str,
    api_key: str,
    messages: list,
    tools: Optional[list] = None,
    timeout: int = 200,
    extra: Optional[dict] = None,
) -> tuple:
    """
    Tool-calling sibling of _call_llm, used by the agentic triage loop.

    Returns (message, usage). *message* is the assistant message the server sent
    back - {"role", "content", "tool_calls", "finish_reason"} and whatever else
    it included (e.g. reasoning_content). Failures follow the same contract as
    _call_llm: nothing is raised, and the error is encoded into the message's
    "content" as an {"is_error": true, ...} payload that _extract_error_reason()
    understands.
    """
    def _err(reason):
        return ({
            "role": "assistant",
            "content": json.dumps({"is_error": True, "score": -1, "reason": reason}),
            "tool_calls": [],
            "finish_reason": "error",
        }, dict(_ZERO_USAGE))

    try:
        import requests
    except ImportError:
        return _err("[ERROR] requests library not installed.")

    url = base_url.rstrip("/") + "/chat/completions"
    payload = {
        "model":       model,
        "messages":    messages,
        "temperature": 0.1,
        "stream":      False,
    }
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = "auto"
    if extra:
        # Server-specific options, e.g. chat_template_kwargs.enable_thinking for
        # reasoning models on llama.cpp / vLLM. Callers handle rejection.
        payload.update(extra)

    try:
        response = requests.post(
            url,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
            json=payload,
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
        choice = data["choices"][0]
        message = dict(choice.get("message") or {})
        message.setdefault("role", "assistant")
        message["content"] = message.get("content") or ""
        message["tool_calls"] = message.get("tool_calls") or []
        message["finish_reason"] = choice.get("finish_reason") or ""
        raw_usage = data.get("usage", {}) or {}
        usage = {
            "prompt_tokens":     raw_usage.get("prompt_tokens", 0),
            "completion_tokens": raw_usage.get("completion_tokens", 0),
            "total_tokens":      raw_usage.get("total_tokens", 0),
        }
        return message, usage
    except requests.exceptions.ConnectionError:
        return _err(f"[ERROR] Cannot connect to LLM at {url}. "
                    f"Ensure your LLM server is running (e.g. ollama serve).")
    except requests.exceptions.Timeout:
        return _err(f"[ERROR] LLM request timed out after {timeout}s.")
    except requests.exceptions.HTTPError as e:
        return _err(f"[ERROR] HTTP {e}")
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        return _err(f"[ERROR] Unexpected LLM response format: {e}")
    except Exception as e:
        logging.error(traceback.format_exc())
        return _err(f"[ERROR] {e}")


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def analyze_events_with_llm(
    events_df: pd.DataFrame,
    min_severity: str = "High",
    llm_provider: str = "llama.cpp",
    llm_base_url: Optional[str] = None,
    llm_model: str = "llama3",
    llm_api_key: Optional[str] = None,
    max_events_per_batch: int = 1,
    llm_context_size: Optional[int] = None,
    timeout: int = 200,
) -> list:
    """
    Analyze each detected event individually with a local LLM.

    For every event at or above *min_severity*, the LLM is asked:
      - Is this event malicious? (true/false)
      - Maliciousness score (0-100)
      - One-sentence reason

    Parameters
    ----------
    events_df     : Combined APT-Hunter results DataFrame (allresults CSV).
    min_severity  : Minimum severity to include. One of:
                    Informational | Low | Medium | High | Critical
    llm_provider  : LLM provider: ollama | llmstudio | llama.cpp
    llm_base_url  : Base URL of the OpenAI-compatible LLM API.
    llm_model     : Model name served by the LLM backend.
    llm_api_key   : API key ("ollama" works for Ollama).
    max_events_per_batch : Upper cap on events sent per LLM request. When
                    llm_context_size is known (given or auto-detected),
                    batches are additionally packed to fit CONTEXT_USAGE_RATIO
                    (80%) of the context window, so actual batches may be
                    smaller than this cap.
    llm_context_size : Model's context window in tokens. If omitted, auto-
                    detection is attempted (Ollama only); if that fails,
                    batching falls back to a fixed size of max_events_per_batch.
    timeout       : HTTP timeout per event request (seconds).

    Returns
    -------
    list of dict, each containing all original event fields plus:
        llm_is_malicious : bool
        llm_score        : int  (0-100)
        llm_reason       : str
    """

    # ── Map Provider Defaults ────────────────────────────────────────────────
    llm_base_url, llm_api_key = _resolve_provider(llm_provider, llm_base_url, llm_api_key)

    # ── Validate severity ────────────────────────────────────────────────────
    normalised_sev = str(min_severity).strip().capitalize()
    if normalised_sev not in SEVERITY_ORDER:
        print(
            f"[LLM] Warning: Unknown severity '{min_severity}'. "
            f"Valid values: {SEVERITY_ORDER}. Defaulting to 'High'."
        )
        normalised_sev = "High"

    print(
        f"\n[LLM] Starting per-event analysis  |  "
        f"model={llm_model}  |  min_severity={normalised_sev}"
    )

    # ── Filter ───────────────────────────────────────────────────────────────
    if "Severity" not in events_df.columns:
        print("[LLM] Warning: 'Severity' column not found in events DataFrame.")
        return []

    filtered_df = _filter_by_severity(events_df, normalised_sev)

    for col in LLM_EVENT_COLUMNS:
        if col not in filtered_df.columns:
            filtered_df[col] = "N/A"

    total_events = len(filtered_df)
    if total_events == 0:
        print(f"[LLM] No events found at severity >= {normalised_sev}. Skipping.")
        return []

    all_rows = [row for _, row in filtered_df.iterrows()]
    batch_cap = max(1, max_events_per_batch)

    if batch_cap > 1:
        context_size = llm_context_size or _detect_model_context_size(llm_base_url, llm_model)
        if context_size:
            source = "provided" if llm_context_size else "auto-detected"
            print(
                f"[LLM] Context window: {context_size} tokens ({source})  |  "
                f"packing batches into {int(CONTEXT_USAGE_RATIO * 100)}% of context "
                f"(cap={batch_cap} events/request)"
            )
            batches = _pack_batches_to_context(all_rows, BATCH_SYSTEM_PROMPT, context_size, batch_cap)
        else:
            print(
                f"[LLM] Context window unknown — using fixed batch size of {batch_cap} "
                f"events/request. Pass llm_context_size to enable context-aware batching."
            )
            batches = [all_rows[i:i + batch_cap] for i in range(0, total_events, batch_cap)]
        avg_size = total_events / len(batches) if batches else 0
        print(f"[LLM] Analysing {total_events} event(s) at severity >= {normalised_sev} "
              f"in {len(batches)} batch(es), avg {avg_size:.1f} events/batch ...\n")
    else:
        batches = [[row] for row in all_rows]
        print(f"[LLM] Analysing {total_events} event(s) at severity >= {normalised_sev} ...\n")

    results = []
    start_time = time.monotonic()
    event_idx = 0
    total_prompt_tokens = 0
    total_completion_tokens = 0
    total_tokens_used = 0

    for batch in batches:
        if batch_cap == 1:
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": _build_event_message(batch[0])},
            ]
            raw_response, usage = _call_llm(
                base_url=llm_base_url, model=llm_model, api_key=llm_api_key,
                messages=messages, timeout=timeout,
            )
            parsed_list = [_parse_llm_json(raw_response)]
        else:
            messages = [
                {"role": "system", "content": BATCH_SYSTEM_PROMPT},
                {"role": "user",   "content": _build_batch_message(batch)},
            ]
            raw_response, usage = _call_llm(
                base_url=llm_base_url, model=llm_model, api_key=llm_api_key,
                messages=messages, timeout=timeout,
            )
            parsed_list = _parse_llm_json_batch(raw_response, len(batch))

        total_prompt_tokens     += usage["prompt_tokens"]
        total_completion_tokens += usage["completion_tokens"]
        total_tokens_used       += usage["total_tokens"]

        for row, parsed in zip(batch, parsed_list):
            event_idx += 1
            result_row = {col: row.get(col, "N/A") for col in events_df.columns}
            if parsed.get("is_error"):
                result_row["LLM Malicious"] = "ERROR"
                result_row["LLM Score"]     = -1
            else:
                result_row["LLM Malicious"] = "YES" if parsed["is_malicious"] else "NO"
                result_row["LLM Score"]     = parsed["score"]
            result_row["LLM Reason"]    = parsed["reason"]
            results.append(result_row)

            if parsed.get("is_error"):
                malicious_label = "⚠️ ERROR"
                extra_info = f" | {parsed['reason']}"
            elif parsed["is_malicious"]:
                malicious_label = "🔴 MALICIOUS"
                extra_info = ""
            else:
                malicious_label = "🟢 clean"
                extra_info = ""
            print(
                f"  [{event_idx:>4}/{total_events}]  score={parsed['score']:>3}/100  "
                f"{malicious_label:15}  {str(row.get('message', 'N/A'))[:60]}{extra_info}"
            )

    elapsed = time.monotonic() - start_time
    malicious_count = sum(1 for r in results if r.get("LLM Malicious") == "YES")
    error_count = sum(1 for r in results if r.get("LLM Malicious") == "ERROR")
    token_line = (
        f"  |  tokens: {total_tokens_used} "
        f"(in={total_prompt_tokens}, out={total_completion_tokens})"
        if total_tokens_used > 0 else "  |  tokens: N/A (provider did not report usage)"
    )
    print(
        f"\n[LLM] Done.  {malicious_count} malicious, {error_count} errors, out of {total_events} events."
        f"  Time: {elapsed:.1f}s{token_line}\n"
    )
    return results


def analyze_single_event(
    event: dict,
    llm_provider: str = "llama.cpp",
    llm_base_url: Optional[str] = None,
    llm_model: str = "llama3",
    llm_api_key: Optional[str] = None,
    timeout: int = 200,
) -> dict:
    """
    Ad-hoc "is this one event malicious?" check, independent of severity
    filtering (used by the web dashboard's per-row "Check with LLM" button).

    *event* is a dict (or pandas Series) with keys matching LLM_EVENT_COLUMNS
    where available: datetime, message, Severity, Detection Domain,
    Event Description, Event ID, Computer Name, Channel, Original Event Log.

    Returns a dict: is_error, is_malicious, score, reason, usage.
    """
    base_url, api_key = _resolve_provider(llm_provider, llm_base_url, llm_api_key)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": _build_event_message(event)},
    ]
    raw_response, usage = _call_llm(base_url=base_url, model=llm_model, api_key=api_key, messages=messages, timeout=timeout)
    parsed = _parse_llm_json(raw_response)
    parsed["usage"] = usage
    return parsed


def explain_event(
    event: dict,
    llm_provider: str = "llama.cpp",
    llm_base_url: Optional[str] = None,
    llm_model: str = "llama3",
    llm_api_key: Optional[str] = None,
    timeout: int = 200,
) -> dict:
    """
    Ask the LLM for a plain-language explanation of a single event (used by
    the web dashboard's per-row "Explain event" button).

    Returns {"explanation": str, "usage": dict} on success, or
    {"error": str, "usage": dict} if the LLM call itself failed.
    """
    base_url, api_key = _resolve_provider(llm_provider, llm_base_url, llm_api_key)
    messages = [
        {"role": "system", "content": EXPLAIN_SYSTEM_PROMPT},
        {"role": "user", "content": _build_event_message(event)},
    ]
    raw_response, usage = _call_llm(base_url=base_url, model=llm_model, api_key=api_key, messages=messages, timeout=timeout)
    error = _extract_error_reason(raw_response)
    if error:
        return {"error": error, "usage": usage}
    return {"explanation": raw_response.strip(), "usage": usage}


def _parse_correlation_json(raw: str, expected_count: int) -> dict:
    """Extract the correlation JSON object, clamping related_event_numbers to
    the valid 1..expected_count range."""
    clean = re.sub(r"```(?:json)?", "", raw, flags=re.IGNORECASE).strip("` \n")
    match = re.search(r"\{.*\}", clean, re.DOTALL)
    if match:
        try:
            data = json.loads(match.group())
            related = []
            for n in data.get("related_event_numbers", []) or []:
                try:
                    n_int = int(n)
                except (TypeError, ValueError):
                    continue
                if 1 <= n_int <= expected_count:
                    related.append(n_int)
            try:
                confidence = int(data.get("confidence", 0))
            except (TypeError, ValueError):
                confidence = 0
            return {
                "correlated": bool(data.get("correlated", False)),
                "related_event_numbers": sorted(set(related)),
                "narrative": str(data.get("narrative", "")).strip(),
                "confidence": confidence,
            }
        except (json.JSONDecodeError, ValueError, TypeError):
            pass
    return {
        "correlated": False,
        "related_event_numbers": [],
        "narrative": f"[Parse error – raw response]: {raw[:300]}",
        "confidence": 0,
    }


def analyze_event_correlation(
    events: list,
    llm_provider: str = "llama.cpp",
    llm_base_url: Optional[str] = None,
    llm_model: str = "llama3",
    llm_api_key: Optional[str] = None,
    timeout: int = 200,
) -> dict:
    """
    Ask the LLM whether a hand-picked set of events are related to each other
    (used by the web dashboard's "Correlate with LLM" multi-select action).

    *events* is a list of dicts (or pandas Series), each shaped like the
    argument to analyze_single_event. Order matters: related_event_numbers in
    the result are 1-based indices into this same list.

    Returns {"correlated": bool, "related_event_numbers": [int], "narrative": str,
    "confidence": int, "usage": dict} on success, or {"error": str, "usage": dict}
    if the LLM call itself failed.
    """
    base_url, api_key = _resolve_provider(llm_provider, llm_base_url, llm_api_key)
    messages = [
        {"role": "system", "content": CORRELATION_SYSTEM_PROMPT},
        {"role": "user", "content": _build_batch_message(events)},
    ]
    raw_response, usage = _call_llm(base_url=base_url, model=llm_model, api_key=api_key, messages=messages, timeout=timeout)
    error = _extract_error_reason(raw_response)
    if error:
        return {"error": error, "usage": usage}
    parsed = _parse_correlation_json(raw_response, len(events))
    parsed["usage"] = usage
    return parsed


REPORT_SYSTEM_PROMPT = textwrap.dedent("""\
    You are an expert cybersecurity incident responder writing a formal, professional incident
    response report for stakeholders (management, legal, and technical teams). You will be given
    a chronological list of security events an analyst has pinned to an incident timeline, each
    with a timestamp, severity, source, affected host, and any analyst notes.

    Write a complete, well-structured incident response report in Markdown, using these sections,
    each as a level-2 Markdown heading ("## Section Name") in this order:

    ## Executive Summary
    ## Incident Overview
    ## Timeline of Events
    ## Technical Findings
    ## Indicators of Compromise
    ## Impact Assessment
    ## Recommendations
    ## Conclusion

    Guidance:
    - Executive Summary: 2-4 sentences, plain language, no jargon, suitable for non-technical readers.
    - Incident Overview: scope, affected systems/hosts, and timeframe.
    - Timeline of Events: a bulleted, chronological list referencing the actual timestamps and events provided.
    - Technical Findings: analysis of what happened technically, referencing MITRE ATT&CK techniques where relevant.
    - Indicators of Compromise: list any hosts, accounts, commands, or artifacts that stand out as IOCs. If none are identifiable, state that explicitly.
    - Impact Assessment: assess likely severity/impact to the organization based on what's known.
    - Recommendations: concrete, actionable remediation and hardening steps.
    - Conclusion: brief closing summary.

    Do not fabricate details not supported by the provided events. If information is insufficient
    for a section, say so briefly rather than inventing specifics. Output ONLY the Markdown report —
    no preamble, no meta-commentary, and no markdown code fences around the whole thing.
""")


def _format_pinned_events(incidents) -> str:
    lines = ["Pinned events (chronological):"]
    for i, inc in enumerate(incidents, start=1):
        lines.append(f"--- EVENT #{i} ---")
        lines.append(f"  Time: {inc.get('date_text') or inc.get('timestamp') or 'Unknown'}")
        lines.append(f"  Severity: {inc.get('severity') or 'N/A'}")
        lines.append(f"  Source: {inc.get('sheet_name') or 'N/A'}")
        lines.append(f"  Computer: {inc.get('computer') or 'N/A'}")
        lines.append(f"  Description: {inc.get('description') or 'N/A'}")
        if inc.get("note"):
            lines.append(f"  Analyst note: {inc.get('note')}")
    return "\n".join(lines)


def _build_report_message(incidents, title, prepared_by):
    lines = []
    if title:
        lines.append(f"Report title requested: {title}")
    if prepared_by:
        lines.append(f"Prepared by: {prepared_by}")
    lines.append(f"Number of pinned events: {len(incidents)}")
    lines.append("")
    lines.append(_format_pinned_events(incidents))
    return "\n".join(lines)


def generate_incident_report(
    incidents: list,
    title: str = "",
    prepared_by: str = "",
    llm_provider: str = "llama.cpp",
    llm_base_url: Optional[str] = None,
    llm_model: str = "llama3",
    llm_api_key: Optional[str] = None,
    timeout: int = 200,
) -> dict:
    """
    Ask the LLM to draft a professional incident-response report (Markdown)
    from the analyst's pinned incident timeline.

    *incidents* is a list of dicts as stored in the incident timeline: each
    has date_text/timestamp, severity, sheet_name, computer, description, note.

    Returns {"content": str, "usage": dict} on success, or
    {"error": str, "usage": dict} if the LLM call itself failed.
    """
    base_url, api_key = _resolve_provider(llm_provider, llm_base_url, llm_api_key)
    messages = [
        {"role": "system", "content": REPORT_SYSTEM_PROMPT},
        {"role": "user", "content": _build_report_message(incidents, title, prepared_by)},
    ]
    raw_response, usage = _call_llm(base_url=base_url, model=llm_model, api_key=api_key, messages=messages, timeout=timeout)
    error = _extract_error_reason(raw_response)
    if error:
        return {"error": error, "usage": usage}
    content = raw_response.strip()
    content = re.sub(r'^```(?:markdown)?\s*', '', content)
    content = re.sub(r'\s*```\s*$', '', content)
    return {"content": content.strip(), "usage": usage}


EXEC_SUMMARY_SYSTEM_PROMPT = textwrap.dedent("""\
    You are an expert cybersecurity incident responder briefing executive and board-level
    stakeholders (CEO, CISO, other C-suite) on a security incident. You will be given a
    chronological list of security events an analyst has pinned to an incident timeline, each
    with a timestamp, severity, source, affected host, and any analyst notes.

    Write a short executive summary suitable for pasting directly into a report for senior
    leadership. Requirements:
      - Plain business language. No technical jargon, log field names, or acronyms unless a
        widely-understood one, and expand it on first use.
      - Open with one sentence stating what happened and when (business terms, not log terms).
      - Cover business impact/risk, current status (e.g. contained, ongoing, resolved — infer
        conservatively from the events; say "under investigation" if unclear), and the single most
        important recommended next step or decision needed from leadership.
      - Target length: 100-180 words, as 1-2 short paragraphs.
      - Optionally follow with a short "Key Points" list of at most 4 bullets if it aids clarity —
        keep each bullet to one short sentence.
      - Do not fabricate details not supported by the provided events. If impact or root cause is
        not yet clear from the events, say so plainly rather than speculating.
      - Confident, calm, factual tone — avoid alarmism and avoid minimizing the incident.

    Output ONLY the summary in Markdown (plain paragraphs, optionally one bullet list) — no
    heading, no preamble, no meta-commentary, and no markdown code fences around the whole thing.
""")


def _build_exec_summary_message(incidents, organization):
    lines = []
    if organization:
        lines.append(f"Organization: {organization}")
    lines.append(f"Number of pinned events: {len(incidents)}")
    lines.append("")
    lines.append(_format_pinned_events(incidents))
    return "\n".join(lines)


def generate_executive_summary(
    incidents: list,
    organization: str = "",
    llm_provider: str = "llama.cpp",
    llm_base_url: Optional[str] = None,
    llm_model: str = "llama3",
    llm_api_key: Optional[str] = None,
    timeout: int = 200,
) -> dict:
    """
    Ask the LLM for a short, plain-language executive summary of the analyst's pinned incident
    timeline, intended for C-level / board-level reporting (used by the web dashboard's
    "Executive Summary" panel on the incident timeline view).

    *incidents* is a list of dicts as stored in the incident timeline: each has
    date_text/timestamp, severity, sheet_name, computer, description, note.

    Returns {"content": str, "usage": dict} on success, or
    {"error": str, "usage": dict} if the LLM call itself failed.
    """
    base_url, api_key = _resolve_provider(llm_provider, llm_base_url, llm_api_key)
    messages = [
        {"role": "system", "content": EXEC_SUMMARY_SYSTEM_PROMPT},
        {"role": "user", "content": _build_exec_summary_message(incidents, organization)},
    ]
    raw_response, usage = _call_llm(base_url=base_url, model=llm_model, api_key=api_key, messages=messages, timeout=timeout)
    error = _extract_error_reason(raw_response)
    if error:
        return {"error": error, "usage": usage}
    content = raw_response.strip()
    content = re.sub(r'^```(?:markdown)?\s*', '', content)
    content = re.sub(r'\s*```\s*$', '', content)
    return {"content": content.strip(), "usage": usage}


def results_to_dataframe(llm_results: list) -> pd.DataFrame:
    """
    Convert the list returned by analyze_events_with_llm() into a DataFrame
    sorted by LLM Score descending.
    """
    if not llm_results:
        return pd.DataFrame(
            columns=["datetime", "message", "Severity", "Detection Domain",
                     "Event Description", "Event ID", "Computer Name",
                     "LLM Malicious", "LLM Score", "LLM Reason"]
        )
    df = pd.DataFrame(llm_results)

    # Put LLM columns first for readability in Excel
    llm_cols = ["LLM Malicious", "LLM Score", "LLM Reason"]
    other_cols = [c for c in df.columns if c not in llm_cols]
    df = df[llm_cols + other_cols]

    return df.sort_values("LLM Score", ascending=False).reset_index(drop=True)


def results_to_markdown(llm_results: list, output_name: str = "") -> str:
    """
    Render per-event LLM analysis results as a Markdown document.
    """
    lines = [
        "# APT-Hunter – LLM Per-Event Maliciousness Report",
        "",
    ]
    if output_name:
        lines += [f"**Run:** `{output_name}`", ""]

    if not llm_results:
        lines.append("_No events matched the requested severity filter._")
        return "\n".join(lines)

    malicious = [r for r in llm_results if r["LLM Malicious"] == "YES"]
    lines += [
        f"**Events Analysed:** {len(llm_results)}  ",
        f"**Classified Malicious:** {len(malicious)}  ",
        f"**Classified Clean:** {len(llm_results) - len(malicious)}  ",
        "",
        "---",
        "",
        "## Results (sorted by score, highest first)",
        "",
        "| Score | Malicious | Detection Rule | Severity | Computer | Reason |",
        "|------:|:---------:|----------------|----------|----------|--------|",
    ]

    sorted_results = sorted(llm_results, key=lambda r: r["LLM Score"], reverse=True)
    for r in sorted_results:
        score   = r.get("LLM Score", 0)
        if r.get("LLM Malicious") == "ERROR":
            mal = "⚠️ ERR"
            score = "N/A"
        elif r.get("LLM Malicious") == "YES":
            mal = "🔴 YES"
        else:
            mal = "🟢 NO"
        rule    = str(r.get("message", "N/A"))[:50]
        sev     = r.get("Severity", "N/A")
        host    = r.get("Computer Name", "N/A")
        reason  = str(r.get("LLM Reason", "")).replace("|", "\\|")[:120]
        lines.append(f"| **{score}** | {mal} | {rule} | {sev} | {host} | {reason} |")

    lines += [
        "",
        "---",
        "",
        "## Detailed Event Breakdown",
        "",
    ]
    for r in sorted_results:
        score  = r.get("LLM Score", 0)
        if r.get("LLM Malicious") == "ERROR":
            mal = "⚠️ ERROR"
            score = "N/A"
        elif r.get("LLM Malicious") == "YES":
            mal = "🔴 MALICIOUS"
        else:
            mal = "🟢 CLEAN"
            
        lines += [
            f"### [{score}/100] {mal} — {r.get('message', 'N/A')}",
            "",
            f"- **Time:** {r.get('datetime', 'N/A')}",
            f"- **Computer:** {r.get('Computer Name', 'N/A')}",
            f"- **Severity:** {r.get('Severity', 'N/A')}",
            f"- **Event ID:** {r.get('Event ID', 'N/A')}",
            f"- **Channel:** {r.get('Channel', 'N/A')}",
            f"- **Description:** {r.get('Event Description', 'N/A')}",
            f"- **LLM Reason:** {r.get('LLM Reason', 'N/A')}",
            "",
        ]

    return "\n".join(lines)
