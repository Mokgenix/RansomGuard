import os
import re
import time
import threading
import psutil
from core.file_monitor import add_alert, add_event, monitor_state

_lock = threading.Lock()

RANSOMWARE_COMMANDS = [
    "vssadmin delete shadows",
    "bcdedit /set recoveryenabled no",
    "wbadmin delete catalog",
    "wmic shadowcopy delete",
    "cipher /w",
    "schtasks /delete",
    "disableantispyware",
    "disableantivirus",
]

PROTECTED_PROCESS_NAMES = {
    'svchost.exe', 'lsass.exe', 'csrss.exe',
    'smss.exe', 'wininit.exe', 'services.exe',
}

FILE_OPEN_THRESHOLD = 80

LOTL_BINARIES = {
    'powershell.exe', 'pwsh.exe', 'certutil.exe',
    'wmic.exe', 'mshta.exe', 'regsvr32.exe',
    'rundll32.exe', 'cscript.exe', 'wscript.exe', 'bitsadmin.exe',
}

LOTL_PATTERNS = [
    (r'-enc\b|-encodedcommand',             'Base64-encoded PowerShell command'),
    (r'-w\s+hidden|-windowstyle\s+hidden',  'Hidden window launch'),
    (r'iex\s*\(|invoke-expression',         'Invoke-Expression (dynamic code)'),
    (r'downloadstring|downloadfile|net\.webclient', 'Downloading remote payload'),
    (r'certutil[^|]*-decode',               'certutil decoding file (payload staging)'),
    (r'certutil[^|]*-urlcache.*https?:',    'certutil downloading from URL'),
    (r'wmic\s+process\s+call\s+create',     'WMI spawning a process'),
    (r'mshta\s+https?:',                    'mshta loading remote script'),
    (r'regsvr32[^|]*/i:https?:',            'regsvr32 loading remote scriptlet'),
    (r'bitsadmin[^|]*/transfer',            'bitsadmin background download'),
    (r'[a-z0-9+/]{80,}={0,2}',             'Long base64 blob in command'),
]
_COMPILED = [(re.compile(p, re.IGNORECASE), d) for p, d in LOTL_PATTERNS]


class ProcessMonitor:
    def __init__(self):
        self._running = False
        self._thread = None
        self.flagged_pids = set()
        self.flagged_lotl_pids = set()

    def scan(self):
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'open_files']):
            try:
                pid = proc.info['pid']
                name = (proc.info['name'] or '')
                name_lower = name.lower()
                cmdline_raw = ' '.join(proc.info['cmdline'] or [])
                cmdline = cmdline_raw.lower()
                open_files = proc.info['open_files'] or []

                # 1. Ransomware backup-destruction commands
                killed = False
                for bad_cmd in RANSOMWARE_COMMANDS:
                    if bad_cmd in cmdline:
                        add_alert("CRITICAL",
                                  f"Ransomware command in '{name}' (PID {pid}): {bad_cmd}",
                                  "Process Monitor")
                        self._kill(proc, bad_cmd)
                        killed = True
                        break
                if killed:
                    continue

                # 2. LotL: trusted binary with abusive arguments
                if name_lower in LOTL_BINARIES and pid not in self.flagged_lotl_pids:
                    for pattern, desc in _COMPILED:
                        if pattern.search(cmdline):
                            short = cmdline_raw[:200] + ('...' if len(cmdline_raw) > 200 else '')
                            add_alert("WARNING",
                                      f"Suspicious '{name}' (PID {pid}): {desc}",
                                      "Process Monitor")
                            add_event(f"Command: {short}", "Process Monitor")
                            self.flagged_lotl_pids.add(pid)
                            with _lock:
                                monitor_state["stats"]["lotl_detections"] += 1
                            break

                # 3. Mass file access
                if len(open_files) > FILE_OPEN_THRESHOLD and pid not in self.flagged_pids:
                    add_alert("WARNING",
                              f"'{name}' (PID {pid}) has {len(open_files)} files open",
                              "Process Monitor")
                    self.flagged_pids.add(pid)

                # 4. System process touching user files
                if name_lower in PROTECTED_PROCESS_NAMES:
                    user_dirs = [os.path.expanduser("~/Documents"),
                                 os.path.expanduser("~/Desktop"),
                                 os.path.expanduser("~/Pictures")]
                    for f in open_files:
                        for ud in user_dirs:
                            if f.path.startswith(ud):
                                add_alert("WARNING",
                                          f"System process '{name}' accessing user files",
                                          "Process Monitor")

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
            except Exception:
                pass

    def _kill(self, proc, reason):
        try:
            pid = proc.info['pid']
            pname = proc.info['name']
            # Kill children first (Fix: children keep running if only parent killed)
            try:
                children = proc.children(recursive=True)
            except Exception:
                children = []
            for child in children:
                try:
                    child.kill()
                    add_event(f"Child process killed: PID {child.pid}", "Process Monitor")
                except Exception:
                    pass
            proc.kill()
            with _lock:
                monitor_state["stats"]["blocked_processes"] += 1
            add_event(f"Process KILLED PID {pid} ({pname}): {reason}", "Process Monitor")
        except Exception as e:
            add_event(f"Kill failed: {e}", "Process Monitor")

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        add_event("Process Monitor active (LotL detection enabled)", "Process Monitor")

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            try:
                self.scan()
            except Exception as e:
                add_event(f"Process monitor error: {e}", "Process Monitor")
            time.sleep(5)