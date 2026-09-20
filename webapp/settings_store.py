"""
Persists LLM configuration (provider, model, endpoint, API key, timeout) as a
global user preference, independent of any single report. A report's SQLite
cache is a disposable artifact — rebuilt whenever its source xlsx changes, and
recreated from scratch for every different report — so settings stored there
would need to be re-entered per report and would vanish on rebuild. Storing
them once under the user's home directory means they're configured a single
time and apply to every report opened afterwards.
"""
import json
import os

SETTINGS_DIR = os.path.join(os.path.expanduser("~"), ".apt-hunter")
SETTINGS_FILE = os.path.join(SETTINGS_DIR, "llm_settings.json")

DEFAULT_SETTINGS = {
    "llm_provider": "ollama",
    "llm_base_url": "",
    "llm_model": "llama3",
    "llm_api_key": "",
    "llm_timeout": "200",
    "triage_auto_pin_threshold": "",   # blank = never auto-pin; findings wait in the review queue
    "triage_max_pivots": "20",
    "triage_agent_enabled": "1",       # off = use the fixed pivot/correlate pipeline
    "triage_agent_rounds": "40",
    "triage_agent_seconds": "900",
    "triage_fast_first_pass": "1",  # skip the model's thinking pass when classifying clusters
}


def load_settings():
    settings = dict(DEFAULT_SETTINGS)
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            saved = json.load(f)
        for key in DEFAULT_SETTINGS:
            if key in saved:
                settings[key] = saved[key]
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass
    return settings


def save_settings(updates):
    settings = load_settings()
    for key in DEFAULT_SETTINGS:
        if key in updates:
            settings[key] = str(updates[key])
    os.makedirs(SETTINGS_DIR, exist_ok=True)
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)
    return settings
