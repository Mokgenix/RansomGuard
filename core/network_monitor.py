import os
import time
import threading
import psutil
from core.file_monitor import add_alert, add_event, monitor_state

_lock = threading.Lock()

SUSPICIOUS_PORTS = {4444, 1337, 9001, 31337, 6667, 6666}

KNOWN_BAD_IPS = {
    "185.220.101.1", "194.165.16.11", "45.142.212.100",
    "91.219.236.166", "198.199.65.189", "185.56.80.65",
    "80.82.77.33",   "89.248.167.131",
}

THREAT_FEED = os.path.join(os.path.dirname(__file__), '..', 'threat_data', 'bad_ips.txt')


def _load_threat_ips():
    ips = set(KNOWN_BAD_IPS)
    if os.path.exists(THREAT_FEED):
        try:
            with open(THREAT_FEED) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        ips.add(line)
        except Exception:
            pass
    return ips


class NetworkMonitor:
    def __init__(self):
        self._running = False
        self._thread = None
        self.bad_ips = _load_threat_ips()
        self.alerted = set()
        # Track which process names have made outbound connections
        self.network_seen_names = set()
        add_event(f"Network Monitor: {len(self.bad_ips)} bad IPs loaded", "Network Monitor")

    def scan(self):
        try:
            conns = psutil.net_connections(kind='inet')
        except Exception:
            return

        for conn in conns:
            if conn.status != 'ESTABLISHED' or not conn.raddr:
                continue
            rip = conn.raddr.ip
            rport = conn.raddr.port
            key = (rip, rport, conn.pid)

            # Track outbound by process name for LotL detection
            if conn.pid:
                try:
                    pname = psutil.Process(conn.pid).name().lower()
                    self.network_seen_names.add(pname)
                except Exception:
                    pass

            if key in self.alerted:
                continue

            if rport in SUSPICIOUS_PORTS:
                add_alert("WARNING",
                          f"Connection to suspicious port {rport} at {rip}",
                          "Network Monitor")
                self.alerted.add(key)
                with _lock:
                    monitor_state["stats"]["network_blocks"] += 1

            if rip in self.bad_ips:
                add_alert("CRITICAL",
                          f"Connection to known malicious IP: {rip}:{rport}",
                          "Network Monitor")
                self.alerted.add(key)
                with _lock:
                    monitor_state["stats"]["network_blocks"] += 1

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        add_event("Network Monitor active", "Network Monitor")

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            try:
                self.scan()
            except Exception as e:
                add_event(f"Network monitor error: {e}", "Network Monitor")
            time.sleep(10)