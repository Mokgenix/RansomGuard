import os
import sys
import json
import string
import threading

_lock = threading.Lock()
CONFIG_PATH = os.path.join(os.path.dirname(__file__), '..', 'config.json')


DEFAULT_CONFIG = {
    "monitored_folders": [],
    "backup_folders": [],
    "backup_password": "11223344",
    "honeypot_names": [],
    "dashboard_password": "ransomguard",
    "single_backup_mode": True,
    "backup_interval_minutes": 60,
}


def load_config():
    with _lock:
        if os.path.exists(CONFIG_PATH):
            try:
                with open(CONFIG_PATH) as f:
                    data = json.load(f)
                cfg = dict(DEFAULT_CONFIG)
                cfg.update(data)
                return cfg
            except Exception:
                pass
        return dict(DEFAULT_CONFIG)


def save_config(cfg):
    with _lock:
        try:
            with open(CONFIG_PATH, 'w') as f:
                json.dump(cfg, f, indent=2)
            return True
        except Exception:
            return False


def list_drives():
    if sys.platform.startswith('win'):
        drives = []
        for letter in string.ascii_uppercase:
            d = f"{letter}:\\"
            if os.path.exists(d):
                drives.append(d)
        return drives
    else:
        paths = [os.sep]
        home = os.path.expanduser("~")
        if home != os.sep:
            paths.append(home)
        return paths


def list_folder(path):
    if not path:
        return {
            "path": "",
            "parent": None,
            "folders": [{"name": d, "path": d} for d in list_drives()],
        }
    path = os.path.normpath(path)
    if not os.path.isdir(path):
        return {"error": f"Not found: {path}"}
    folders = []
    try:
        for entry in sorted(os.listdir(path), key=str.lower):
            full = os.path.join(path, entry)
            if os.path.isdir(full) and not entry.startswith('.'):
                if entry not in ('$RECYCLE.BIN', 'System Volume Information'):
                    folders.append({"name": entry, "path": full})
    except (PermissionError, OSError) as e:
        return {"error": str(e)}

    is_root = (sys.platform.startswith('win') and len(path) <= 3) or path == os.sep
    parent = None if is_root else os.path.dirname(path)
    return {"path": path, "parent": parent, "folders": folders}


def folder_stats(path):
    if not path or not os.path.exists(path):
        return {"error": "Not found"}
    count, size = 0, 0
    try:
        for root, dirs, files in os.walk(path):
            for f in files:
                count += 1
                if count > 5000:
                    return {"file_count": "5000+", "size_mb": "-"}
                try:
                    size += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
    except Exception as e:
        return {"error": str(e)}
    return {"file_count": count, "size_mb": round(size / 1048576, 1)}