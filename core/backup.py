import os
import time
import shutil
import hashlib
import zipfile
import threading
from datetime import datetime
from core.file_monitor import add_alert, add_event, monitor_state

_lock = threading.Lock()


class BackupManager:
    """
    Feature 5: single_backup_mode = True means each backup
    destination keeps exactly ONE zip. The old file is deleted
    before the new one is written, so storage stays bounded.

    Feature 6: backups are password-protected with a ZIP
    encryption password (default '11223344').

    Multiple backup_dirs are supported (Feature 2): the same
    snapshot is written to every configured backup destination.
    """

    def __init__(self, source_dirs, backup_dirs, password="11223344",
                 interval_minutes=60, single_backup_mode=True):
        self.source_dirs = [d for d in source_dirs if d]
        self.backup_dirs = [d for d in backup_dirs if d]
        self.password = password
        self.interval = interval_minutes * 60
        self.single_backup_mode = single_backup_mode
        self._running = False
        self._thread = None

        for bd in self.backup_dirs:
            os.makedirs(bd, exist_ok=True)

    def create_snapshot(self):
        if not self.backup_dirs:
            add_alert("WARNING", "No backup destination configured", "Backup")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"backup_{timestamp}.zip"

        # Build zip in memory / temp first, then copy to each destination
        import tempfile
        tmp = tempfile.mktemp(suffix='.zip')
        file_count = 0

        try:
            # zipfile's built-in password uses ZIP 2.0 encryption (legacy but
            # universally compatible on Windows). For a local protection layer
            # this is fine -- it prevents casual access / explorer double-click.
            with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED) as zf:
                pwd_bytes = self.password.encode('utf-8')
                for src in self.source_dirs:
                    if not os.path.isdir(src):
                        continue
                    for root, dirs, files in os.walk(src):
                        for fname_inner in files:
                            fpath = os.path.join(root, fname_inner)
                            try:
                                arcname = os.path.relpath(fpath, os.path.dirname(src))
                                zf.write(fpath, arcname)
                                file_count += 1
                            except (PermissionError, OSError):
                                pass

            # Set password using setpassword on open for read; for write we
            # use pyminizip if available, else fall back to 7z CLI, else
            # plain zip with a note. We try the best available method.
            protected_tmp = self._apply_password(tmp, timestamp)

            size_mb = os.path.getsize(protected_tmp) / (1024 * 1024)

            for bd in self.backup_dirs:
                try:
                    os.makedirs(bd, exist_ok=True)
                    dest = os.path.join(bd, f"backup_{timestamp}.zip")

                    if self.single_backup_mode:
                        # Delete ALL existing zips in this backup dir first
                        for old in os.listdir(bd):
                            if old.endswith('.zip'):
                                try:
                                    os.remove(os.path.join(bd, old))
                                except OSError:
                                    pass

                    shutil.copy2(protected_tmp, dest)
                    add_event(
                        f"Backup saved: {file_count} files ({size_mb:.1f} MB) "
                        f"-> {bd}",
                        "Backup"
                    )
                except Exception as e:
                    add_alert("WARNING", f"Backup copy failed to {bd}: {e}", "Backup")

        except Exception as e:
            add_alert("WARNING", f"Backup creation failed: {e}", "Backup")
            return
        finally:
            for f in [tmp]:
                try:
                    if os.path.exists(f):
                        os.remove(f)
                except OSError:
                    pass

        with _lock:
            monitor_state["stats"]["last_backup"] = datetime.now().strftime("%H:%M:%S")

    def _apply_password(self, zip_path, timestamp):
        """
        Attempt to create a password-protected ZIP.
        Strategy:
          1. Try pyminizip (pure-Python, strong encryption)
          2. Try 7z CLI
          3. Fall back: rename and note (protection not applied)
        """
        protected = zip_path.replace('.zip', '_protected.zip')

        # Method 1: pyminizip
        try:
            import pyminizip
            import tempfile, os as _os
            # collect all files from the plain zip, repack with password
            with zipfile.ZipFile(zip_path, 'r') as zf:
                extract_tmp = tempfile.mkdtemp()
                zf.extractall(extract_tmp)
                files = []
                prefixes = []
                for root, dirs, fnames in _os.walk(extract_tmp):
                    for fn in fnames:
                        fp = _os.path.join(root, fn)
                        files.append(fp)
                        rel = _os.path.relpath(_os.path.dirname(fp), extract_tmp)
                        prefixes.append(rel if rel != '.' else '')
                pyminizip.compress_multiple(files, prefixes, protected, self.password, 5)
                shutil.rmtree(extract_tmp, ignore_errors=True)
            add_event("Backup password-protected via pyminizip", "Backup")
            return protected
        except ImportError:
            pass
        except Exception as e:
            add_event(f"pyminizip error: {e}", "Backup")

        # Method 2: 7z CLI
        try:
            import subprocess
            result = subprocess.run(
                ['7z', 'a', f'-p{self.password}', '-tzip', '-mem=AES256',
                 protected, zip_path],
                capture_output=True, timeout=120
            )
            if result.returncode == 0:
                add_event("Backup password-protected via 7-Zip", "Backup")
                return protected
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            pass

        # Method 3: fallback — use the plain zip, warn user
        add_event(
            "Note: install pyminizip or 7-Zip for password protection. "
            "Backup saved without password this time.",
            "Backup"
        )
        return zip_path

    def list_backups(self):
        results = []
        seen = set()
        for bd in self.backup_dirs:
            if not os.path.isdir(bd):
                continue
            for fname in sorted(os.listdir(bd), reverse=True):
                if fname.endswith('.zip'):
                    fpath = os.path.join(bd, fname)
                    if fpath not in seen:
                        seen.add(fpath)
                        size_mb = os.path.getsize(fpath) / (1024 * 1024)
                        results.append({
                            "name": fname,
                            "size": f"{size_mb:.1f} MB",
                            "path": fpath,
                            "dir": bd,
                        })
        return results

    def start(self):
        self.create_snapshot()
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        add_event(f"Backup Manager active (every {self.interval//60} min, "
                  f"single-file mode={self.single_backup_mode})", "Backup")

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            time.sleep(self.interval)
            if self._running:
                self.create_snapshot()