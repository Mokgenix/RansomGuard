"""
RansomGuard v2 - Complete Ransomware Prevention Tool
Run: python app.py
Open: http://localhost:5000
"""

import os
import sys
import json
import secrets
import threading
import requests as http_requests
from datetime import datetime
from flask import Flask, render_template, jsonify, request

sys.path.insert(0, os.path.dirname(__file__))

from core.file_monitor import monitor_state, add_event, add_alert, FileWatcher
from core.honeypot import HoneypotManager
from core.process_monitor import ProcessMonitor
from core.backup import BackupManager
from core.network_monitor import NetworkMonitor
from core import folder_browser

# ── directories ──────────────────────────────
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
HONEYPOT_DIR = os.path.join(BASE_DIR, "honeypots")
THREAT_DIR   = os.path.join(BASE_DIR, "threat_data")

for d in (HONEYPOT_DIR, THREAT_DIR):
    os.makedirs(d, exist_ok=True)

DEFAULT_DIRS = [
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Pictures"),
    os.path.expanduser("~/Downloads"),
]
DEFAULT_BACKUP_DIR = os.path.join(BASE_DIR, "backups")
os.makedirs(DEFAULT_BACKUP_DIR, exist_ok=True)

# ── Flask ─────────────────────────────────────
app = Flask(__name__, template_folder='templates', static_folder='static')

# ── Auth ──────────────────────────────────────
# Dashboard password — set once at startup, read from config.
# In-memory session tokens: cleared automatically when server stops
# because they only live in this dict (never written to disk).
_sessions = set()   # valid session tokens for this server run
_sessions_lock = threading.Lock()

OPENROUTER_API_KEY = "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"
OPENROUTER_MODEL   = "nvidia/nemotron-3-ultra-550b-a55b:free"
DASHBOARD_PASSWORD = "ransomguard"   # default — user changes in Settings

def _get_dashboard_password():
    """Always read from config so Settings changes take effect immediately."""
    cfg = folder_browser.load_config()
    return cfg.get("dashboard_password") or DASHBOARD_PASSWORD

def _make_session():
    tok = secrets.token_urlsafe(32)
    with _sessions_lock:
        _sessions.add(tok)
    return tok

def _valid_session(tok):
    with _sessions_lock:
        return tok in _sessions

def _require_auth():
    """Return True if the request carries a valid session token."""
    tok = request.cookies.get("rg_session") or request.headers.get("X-RG-Session", "")
    return _valid_session(tok)

components = {
    "file_watcher": None,
    "honeypot":     None,
    "process":      None,
    "backup":       None,
    "network":      None,
}


# ── helpers ───────────────────────────────────
def get_cfg():
    return folder_browser.load_config()

def monitored_dirs():
    cfg = get_cfg()
    return cfg.get("monitored_folders") or DEFAULT_DIRS

def backup_dirs():
    cfg = get_cfg()
    return cfg.get("backup_folders") or [DEFAULT_BACKUP_DIR]


# ── lifecycle ─────────────────────────────────
def start_all():
    if monitor_state["running"]:
        return
    monitor_state["running"] = True
    cfg = get_cfg()

    src  = monitored_dirs()
    bdst = backup_dirs()
    pwd  = cfg.get("backup_password", "11223344")
    single = cfg.get("single_backup_mode", True)
    interval = cfg.get("backup_interval_minutes", 60)

    fw = FileWatcher(src);          fw.start();  components["file_watcher"] = fw
    hp = HoneypotManager(src, HONEYPOT_DIR)
    hp.start();                                  components["honeypot"] = hp
    pm = ProcessMonitor();          pm.start();  components["process"] = pm
    bm = BackupManager(src, bdst, password=pwd,
                       interval_minutes=interval,
                       single_backup_mode=single)
    bm.start();                                  components["backup"] = bm
    nm = NetworkMonitor();          nm.start();  components["network"] = nm

    add_event(f"All 7 layers active | watching {len(src)} folder(s)", "System")


def stop_all():
    if not monitor_state["running"]:
        return
    monitor_state["running"] = False
    for k, c in components.items():
        if c and hasattr(c, 'stop'):
            c.stop()
            components[k] = None
    add_event("All monitors stopped", "System")


def restart_all():
    was = monitor_state["running"]
    if was:
        stop_all()
        import time; time.sleep(0.6)
        start_all()


# ── dashboard ─────────────────────────────────
@app.route('/')
def index():
    return render_template('dashboard.html')


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json(silent=True) or {}
    entered = (data.get("password") or "").strip()
    if entered == _get_dashboard_password():
        tok = _make_session()
        resp = jsonify({"status": "ok", "token": tok})
        # Cookie: session only — no max_age means it dies when browser tab closes
        resp.set_cookie("rg_session", tok, httponly=True, samesite="Strict")
        return resp
    return jsonify({"error": "Wrong password"}), 401


@app.route('/api/logout', methods=['POST'])
def api_logout():
    tok = request.cookies.get("rg_session") or request.headers.get("X-RG-Session", "")
    with _sessions_lock:
        _sessions.discard(tok)
    resp = jsonify({"status": "ok"})
    resp.delete_cookie("rg_session")
    return resp


@app.route('/api/state')
def api_state():
    if not _require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    cfg = get_cfg()
    bm = components.get("backup")
    return jsonify({
        "running":         monitor_state["running"],
        "stats":           monitor_state["stats"],
        "alerts":          monitor_state["alerts"][:60],
        "recent_events":   monitor_state["recent_events"][:30],
        "incident_log":    monitor_state["incident_log"][:100],
        "backups":         bm.list_backups() if bm else [],
        "timestamp":       datetime.now().strftime("%H:%M:%S"),
        "monitored_dirs":  monitored_dirs(),
        "backup_dirs":     backup_dirs(),
        "config":          cfg,
    })


@app.route('/api/start', methods=['POST'])
def api_start():
    if not _require_auth(): return jsonify({"error": "Unauthorized"}), 401
    threading.Thread(target=start_all, daemon=True).start()
    return jsonify({"status": "started"})


@app.route('/api/stop', methods=['POST'])
def api_stop():
    if not _require_auth(): return jsonify({"error": "Unauthorized"}), 401
    stop_all()
    return jsonify({"status": "stopped"})


@app.route('/api/backup_now', methods=['POST'])
def api_backup_now():
    if not _require_auth(): return jsonify({"error": "Unauthorized"}), 401
    bm = components.get("backup")
    if bm:
        threading.Thread(target=bm.create_snapshot, daemon=True).start()
    else:
        cfg = get_cfg()
        tmp = BackupManager(
            monitored_dirs(), backup_dirs(),
            password=cfg.get("backup_password", "11223344"),
            interval_minutes=999999,
            single_backup_mode=cfg.get("single_backup_mode", True),
        )
        threading.Thread(target=tmp.create_snapshot, daemon=True).start()
    return jsonify({"status": "ok"})


@app.route('/api/clear_alerts', methods=['POST'])
def api_clear():
    if not _require_auth(): return jsonify({"error": "Unauthorized"}), 401
    monitor_state["alerts"].clear()
    monitor_state["recent_events"].clear()
    add_event("Alerts cleared", "System")
    return jsonify({"status": "ok"})


@app.route('/api/save_config', methods=['POST'])
def api_save_config():
    if not _require_auth(): return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    cfg = folder_browser.load_config()

    if "monitored_folders" in data:
        valid = [p for p in data["monitored_folders"] if os.path.isdir(p)]
        cfg["monitored_folders"] = valid

    if "backup_folders" in data:
        valid = []
        for p in data["backup_folders"]:
            try:
                os.makedirs(p, exist_ok=True)
                valid.append(p)
            except Exception:
                pass
        cfg["backup_folders"] = valid

    for key in ("backup_password", "single_backup_mode",
                "backup_interval_minutes", "dashboard_password"):
        if key in data:
            cfg[key] = data[key]

    if "honeypot_names" in data:
        cfg["honeypot_names"] = [n.strip() for n in data["honeypot_names"] if n.strip()]

    folder_browser.save_config(cfg)
    restart_all()
    return jsonify({"status": "ok", "config": cfg})


@app.route('/api/browse')
def api_browse():
    if not _require_auth(): return jsonify({"error": "Unauthorized"}), 401
    return jsonify(folder_browser.list_folder(request.args.get('path', '')))


@app.route('/api/folder_stats')
def api_folder_stats():
    if not _require_auth(): return jsonify({"error": "Unauthorized"}), 401
    return jsonify(folder_browser.folder_stats(request.args.get('path', '')))


@app.route('/api/redeploy_honeypots', methods=['POST'])
def api_redeploy():
    if not _require_auth(): return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    hp = components.get("honeypot")
    custom_names = data.get("names") or None
    ai_contents  = data.get("ai_contents") or None
    if hp:
        threading.Thread(target=hp.redeploy,
                         kwargs={"custom_names": custom_names,
                                 "ai_contents": ai_contents},
                         daemon=True).start()
        return jsonify({"status": "redeploying"})
    return jsonify({"status": "not running"}), 400


@app.route('/api/ai_chat', methods=['POST'])
def api_ai_chat():
    if not _require_auth(): return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    user_msg = data.get("message", "").strip()
    history  = data.get("history", [])

    if not user_msg:
        return jsonify({"error": "Empty message"}), 400

    messages = []
    for h in history[-20:]:
        if h.get("role") in ("user", "assistant") and h.get("content"):
            messages.append({"role": h["role"], "content": h["content"]})
    messages.append({"role": "user", "content": user_msg})

    system_prompt = (
        "You are RansomGuard AI, a security assistant inside a ransomware prevention tool. "
        "Help the user understand alerts, explain ransomware threats, suggest improvements, "
        "and help configure the tool. Be concise and friendly."
    )

    try:
        resp = http_requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
                "HTTP-Referer": "http://localhost:5000",
                "X-Title": "RansomGuard",
            },
            json={
                "model": OPENROUTER_MODEL,
                "max_tokens": 1024,
                "messages": [{"role": "system", "content": system_prompt}] + messages,
            },
            timeout=60,
        )
        raw = resp.json()

        # Non-200 status
        if resp.status_code != 200:
            err = raw.get("error", {})
            msg = err.get("message") or str(raw)[:300]
            return jsonify({"error": f"API {resp.status_code}: {msg}"}), 502

        # 200 but no choices (model overloaded / quota etc.)
        choices = raw.get("choices")
        if not choices:
            detail = raw.get("error") or raw.get("message") or str(raw)[:300]
            return jsonify({"error": f"No response from model: {detail}"}), 502

        reply = choices[0]["message"]["content"]
        return jsonify({"reply": reply})

    except http_requests.Timeout:
        return jsonify({"error": "AI request timed out (60s)"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/ai_generate_honeypot', methods=['POST'])
def api_ai_gen_honeypot():
    if not _require_auth(): return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    names = data.get("names", [])
    if not names:
        return jsonify({"error": "No file names provided"}), 400

    contents = []
    for name in names[:10]:
        prompt = (
            f"Generate realistic plain-text content for a file named '{name}'. "
            f"Make it look like a genuine office document. "
            f"Include realistic data (names, dates, numbers, references). "
            f"Keep it under 300 words. Return ONLY the document content."
        )
        try:
            resp = http_requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "http://localhost:5000",
                    "X-Title": "RansomGuard",
                },
                json={
                    "model": OPENROUTER_MODEL,
                    "max_tokens": 400,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=60,
            )
            raw = resp.json()
            choices = raw.get("choices")
            if resp.status_code == 200 and choices:
                contents.append(choices[0]["message"]["content"])
            else:
                contents.append(None)
        except Exception:
            contents.append(None)

    return jsonify({"contents": contents})


# ── main ──────────────────────────────────────
if __name__ == '__main__':
    print("\n+--------------------------------------------------+")
    print("|  RansomGuard v2 - Ransomware Prevention Tool     |")
    print("|  Dashboard -> http://localhost:5000              |")
    print("|  Press Ctrl+C to stop                           |")
    print("+--------------------------------------------------+\n")
    app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)