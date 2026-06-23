import os
import json
import time
import random
import hashlib
import threading
from datetime import datetime
from core.file_monitor import add_alert, add_event, monitor_state

_lock = threading.Lock()
ROTATION_DAYS = 30

DEFAULT_NAMES = [
    "Q{q}_invoice_final_v{v}.docx",
    "Q{q}_expenses_report.xlsx",
    "passport_scan_{y}.pdf",
    "salary_review_{y}.docx",
    "tax_return_{y}_draft.pdf",
    "bank_statement_{m}_{y}.pdf",
    "insurance_policy_{y}.pdf",
    "meeting_notes_{m}_{y}.docx",
    "project_budget_Q{q}.xlsx",
    "client_contract_draft.docx",
    "resume_{y}_updated.docx",
    "medical_records_{y}.pdf",
    "annual_review_{y}.docx",
    "vendor_agreement_{y}.pdf",
    "onboarding_checklist.pdf",
    "performance_goals_{y}.docx",
]

MONTHS = ["jan","feb","mar","apr","may","jun",
          "jul","aug","sep","oct","nov","dec"]


def _pick_name(pool, used):
    year = datetime.now().year
    for _ in range(40):
        t = random.choice(pool)
        name = t.format(
            q=random.randint(1,4),
            v=random.randint(1,3),
            y=year - random.randint(0,2),
            m=random.choice(MONTHS),
        ) if '{' in t else t
        if name not in used:
            return name
    return f"document_{random.randint(10000,99999)}.docx"


def _generate_content(name, ai_content=None):
    """Use AI-generated content if provided, otherwise generate placeholder."""
    if ai_content:
        return ai_content.encode('utf-8', errors='replace')
    ref = hashlib.md5(name.encode()).hexdigest()[:16]
    ts = datetime.now().strftime("%Y-%m-%d")
    lines = [
        f"Document Reference: {ref}",
        f"Date: {ts}",
        f"Status: Active",
        f"Version: 1.0",
        f"",
        f"This document contains confidential information.",
        f"Unauthorized access is prohibited.",
        f"",
        f"Checksum: {ref[:8].upper()}",
    ]
    return "\n".join(lines).encode('utf-8')


class HoneypotManager:
    """
    Places realistic decoy files across monitored directories.
    Supports:
    - Custom file names chosen by the user (Feature 4)
    - AI-generated realistic content via the API key (Feature 4)
    - Rotation every ROTATION_DAYS so pattern can't be learned
    - Spread across subdirectories, not just root
    """

    def __init__(self, directories, meta_dir):
        self.directories = [d for d in directories if d]
        self.meta_dir = meta_dir
        self.meta_path = os.path.join(meta_dir, "hp_meta.json")
        self.honeypots = {}
        self._running = False
        self._thread = None
        os.makedirs(meta_dir, exist_ok=True)

    def _load_meta(self):
        if os.path.exists(self.meta_path):
            try:
                with open(self.meta_path) as f:
                    return json.load(f)
            except Exception:
                pass
        return {"rotated_at": 0, "paths": []}

    def _save_meta(self, ts, paths):
        try:
            with open(self.meta_path, 'w') as f:
                json.dump({"rotated_at": ts, "paths": paths}, f)
        except Exception:
            pass

    def deploy(self, custom_names=None, ai_contents=None, force=False):
        meta = self._load_meta()
        age_days = (time.time() - meta.get("rotated_at", 0)) / 86400
        if force or age_days >= ROTATION_DAYS or not meta.get("paths"):
            self._rotate(custom_names, ai_contents)
        else:
            self._reload(meta["paths"])

    def _rotate(self, custom_names=None, ai_contents=None):
        for p in self._load_meta().get("paths", []):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except OSError:
                pass

        self.honeypots = {}
        used = set()
        name_pool = list(custom_names) if custom_names else list(DEFAULT_NAMES)
        valid_dirs = [d for d in self.directories if os.path.isdir(d)]
        ai_idx = 0

        for d in valid_dirs:
            targets = [d]
            try:
                subs = [os.path.join(d, s) for s in os.listdir(d)
                        if os.path.isdir(os.path.join(d, s)) and not s.startswith('.')]
                if subs:
                    targets.append(random.choice(subs))
            except OSError:
                pass

            for target in targets:
                for _ in range(random.randint(1, 2)):
                    name = _pick_name(name_pool, used)
                    used.add(name)
                    path = os.path.join(target, name)
                    if os.path.exists(path):
                        continue
                    try:
                        ai_c = None
                        if ai_contents and ai_idx < len(ai_contents):
                            ai_c = ai_contents[ai_idx]
                            ai_idx += 1
                        content = _generate_content(name, ai_c)
                        with open(path, 'wb') as f:
                            f.write(content)
                        self.honeypots[path] = hashlib.sha256(content).hexdigest()
                    except OSError:
                        pass

        now = time.time()
        self._save_meta(now, list(self.honeypots.keys()))
        n = len(self.honeypots)
        add_event(f"Honeypots deployed: {n} decoy files across {len(valid_dirs)} folder(s)", "Honeypot")
        with _lock:
            monitor_state["stats"]["honeypot_status"] = "Active" if n else "Inactive"

    def _reload(self, paths):
        self.honeypots = {}
        for p in paths:
            if os.path.exists(p):
                try:
                    with open(p, 'rb') as f:
                        self.honeypots[p] = hashlib.sha256(f.read()).hexdigest()
                except OSError:
                    pass
        if self.honeypots:
            add_event(f"Honeypots: {len(self.honeypots)} existing files reloaded", "Honeypot")
            with _lock:
                monitor_state["stats"]["honeypot_status"] = "Active"
        else:
            self._rotate()

    def check(self):
        triggered = False
        for path, orig in list(self.honeypots.items()):
            if not os.path.exists(path):
                add_alert("CRITICAL", f"Decoy file DELETED: {os.path.basename(path)}", "Honeypot")
                triggered = True
                continue
            try:
                with open(path, 'rb') as f:
                    cur = hashlib.sha256(f.read()).hexdigest()
                if cur != orig:
                    add_alert("CRITICAL", f"Decoy file MODIFIED: {os.path.basename(path)}", "Honeypot")
                    triggered = True
            except Exception as e:
                add_event(f"Honeypot check error: {e}", "Honeypot")

        with _lock:
            if not self.honeypots:
                monitor_state["stats"]["honeypot_status"] = "Inactive"
            elif triggered:
                monitor_state["stats"]["honeypot_status"] = "TRIGGERED"
            else:
                monitor_state["stats"]["honeypot_status"] = "Safe"
        return triggered

    def redeploy(self, custom_names=None, ai_contents=None):
        """Force redeploy with new names/content (called from dashboard)."""
        self._rotate(custom_names, ai_contents)

    def start(self):
        self.deploy()
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            try:
                self.check()
            except Exception as e:
                add_event(f"Honeypot error: {e}", "Honeypot")
            time.sleep(15)