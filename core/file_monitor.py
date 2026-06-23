import os
import time
import math
import threading
from datetime import datetime

RANSOMWARE_EXTENSIONS = {
    '.locked', '.crypto', '.crypt', '.enc', '.encrypted',
    '.locky', '.cerber', '.zepto', '.wcry', '.wncry',
    '.globe', '.xtbl', '.ezz', '.exx', '.crypted',
    '.vault', '.toxcrypt', '.magic', '.SUPERCRYPT',
}

monitor_state = {
    "running": False,
    "alerts": [],
    "stats": {
        "files_watched": 0,
        "alerts_triggered": 0,
        "modifications_per_min": 0,
        "entropy_checks": 0,
        "honeypot_status": "Inactive",
        "last_backup": "Never",
        "blocked_processes": 0,
        "cumulative_window_files": 0,
        "network_blocks": 0,
        "lotl_detections": 0,
    },
    "recent_events": [],
    "incident_log": [],
    "config": {
        "monitored_folders": [],
        "backup_folders": [],
        "backup_password": "11223344",
        "honeypot_names": [],
        "ai_api_key": "",
        "single_backup_mode": True,
    }
}

_lock = threading.Lock()


def add_alert(level, message, source="System"):
    with _lock:
        entry = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "level": level,
            "message": message,
            "source": source,
        }
        monitor_state["alerts"].insert(0, entry)
        monitor_state["alerts"] = monitor_state["alerts"][:200]
        monitor_state["stats"]["alerts_triggered"] += 1
        monitor_state["recent_events"].insert(0, entry)
        monitor_state["recent_events"] = monitor_state["recent_events"][:40]
        monitor_state["incident_log"].insert(0, entry)
        monitor_state["incident_log"] = monitor_state["incident_log"][:1000]


def add_event(message, source="Monitor"):
    with _lock:
        entry = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "level": "INFO",
            "message": message,
            "source": source,
        }
        monitor_state["recent_events"].insert(0, entry)
        monitor_state["recent_events"] = monitor_state["recent_events"][:40]
        monitor_state["incident_log"].insert(0, entry)
        monitor_state["incident_log"] = monitor_state["incident_log"][:1000]


PLAIN_TEXT_EXTENSIONS = {
    '.txt', '.py', '.js', '.html', '.csv', '.xml',
    '.json', '.md', '.log', '.ini', '.cfg', '.bat',
    '.ps1', '.vbs',
}


def calculate_entropy(file_path, sample_size=8192):
    try:
        with open(file_path, 'rb') as f:
            data = f.read(sample_size)
        if not data:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        entropy = 0.0
        n = len(data)
        for c in counts:
            if c:
                p = c / n
                entropy -= p * math.log2(p)
        return round(entropy, 3)
    except Exception:
        return 0.0


def check_entropy(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    if ext in PLAIN_TEXT_EXTENSIONS:
        score = calculate_entropy(file_path)
        with _lock:
            monitor_state["stats"]["entropy_checks"] += 1
        if score > 7.2:
            add_alert("CRITICAL",
                      f"High entropy ({score}/8.0) in {os.path.basename(file_path)} - may be encrypted",
                      "Entropy Checker")
            return True, score
    return False, 0.0


class FileWatcher:
    def __init__(self, directories):
        self.directories = [d for d in directories if d and os.path.isdir(d)]
        self.mod_times = {}
        self.event_ts = []
        self.burst_window = 10
        self.burst_threshold = 20
        self.rename_threshold = 10
        self.slow_window = 6 * 3600
        self.slow_threshold = 50
        self.slow_events = []
        self.slow_alerted_at = 0
        self._running = False
        self._thread = None

    def _scan(self):
        current = {}
        for d in self.directories:
            if not os.path.isdir(d):
                continue
            for root, dirs, files in os.walk(d):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        current[fpath] = os.path.getmtime(fpath)
                    except OSError:
                        pass

        for path, mtime in current.items():
            if path not in self.mod_times:
                self._on_created(path)
            elif self.mod_times[path] != mtime:
                self._on_modified(path)

        old, new = set(self.mod_times), set(current)
        if old - new and new - old:
            for d in old - new:
                self._on_renamed(d)

        self.mod_times = current
        with _lock:
            monitor_state["stats"]["files_watched"] = len(current)

    def _record_burst(self, etype, path):
        now = time.time()
        self.event_ts.append((etype, path, now))
        self.event_ts = [e for e in self.event_ts if now - e[2] < self.burst_window]
        mods = sum(1 for e in self.event_ts if e[0] in ('modify', 'create'))
        renames = sum(1 for e in self.event_ts if e[0] == 'rename')
        with _lock:
            monitor_state["stats"]["modifications_per_min"] = mods * (60 // self.burst_window)
        if mods >= self.burst_threshold:
            add_alert("CRITICAL", f"Burst: {mods} file changes in {self.burst_window}s", "File Watcher")
        if renames >= self.rename_threshold:
            add_alert("CRITICAL", f"Mass rename: {renames} files in {self.burst_window}s", "File Watcher")

    def _record_slow(self, path):
        now = time.time()
        self.slow_events.append((path, now))
        self.slow_events = [e for e in self.slow_events if e[1] >= now - self.slow_window]
        unique = len({p for p, _ in self.slow_events})
        with _lock:
            monitor_state["stats"]["cumulative_window_files"] = unique
        if unique >= self.slow_threshold and now - self.slow_alerted_at > 600:
            add_alert("WARNING",
                      f"Slow-burn: {unique} unique files changed in 6h - possible patient ransomware",
                      "File Watcher")
            self.slow_alerted_at = now

    def _on_created(self, path):
        self._record_burst('create', path)
        self._record_slow(path)
        ext = os.path.splitext(path)[1].lower()
        if ext in RANSOMWARE_EXTENSIONS:
            add_alert("CRITICAL", f"Ransomware extension: {os.path.basename(path)}", "File Watcher")
        check_entropy(path)

    def _on_modified(self, path):
        self._record_burst('modify', path)
        self._record_slow(path)
        check_entropy(path)

    def _on_renamed(self, path):
        self._record_burst('rename', path)

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _loop(self):
        add_event("File Watcher active (burst + slow-burn detection)", "File Watcher")
        while self._running:
            try:
                self._scan()
            except Exception as e:
                add_event(f"File Watcher error: {e}", "File Watcher")
            time.sleep(3)