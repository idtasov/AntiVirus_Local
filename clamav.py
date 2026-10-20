"""
ClamAV integration: finding it, checking it actually works, and scanning with it.

ClamAV ships two scanners:
  clamscan   standalone. Loads the whole virus database (~1 GB RAM, 10-30 s) on every
             run, so it's fine for one big batch but far too slow to call per file.
  clamdscan  a thin client for the clamd background service, which keeps the database
             loaded. Fast per file, but only works while clamd is running.

So Sentinel uses clamdscan per file when the service answers, and otherwise runs
clamscan once over the whole scan target after its own pass (a "batch pass").

Finding it: the Windows installer puts ClamAV in C:\\Program Files\\ClamAV and doesn't add
it to PATH, so besides PATH we look in the usual install folders and in a folder you can
set in Settings.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time

IS_WINDOWS = os.name == "nt"
NO_WINDOW = 0x08000000 if IS_WINDOWS else 0   # don't flash a console window per call


def default_dirs() -> list[str]:
    if IS_WINDOWS:
        dirs = [os.path.join(os.environ.get(v, d), "ClamAV")
                for v, d in (("ProgramFiles", r"C:\Program Files"), ("ProgramFiles(x86)", r"C:\Program Files (x86)"))]
        return dirs + [r"C:\ClamAV"]
    if sys.platform == "darwin":
        return ["/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin"]
    return ["/usr/bin", "/usr/local/bin", "/snap/bin"]


def find(custom_dir: str = "") -> dict:
    """Locate clamscan / clamdscan. Order: your folder from Settings, PATH, usual install folders."""
    found, searched = {}, []
    places = ([custom_dir] if custom_dir else []) + [None] + default_dirs()   # None = PATH
    for name in ("clamscan", "clamdscan"):
        for place in places:
            hit = shutil.which(name, path=place) if place else shutil.which(name)
            if hit:
                found[name] = hit
                break
    for place in places:
        searched.append(place or "PATH")
    return {"clamscan": found.get("clamscan"), "clamdscan": found.get("clamdscan"), "searched": searched}


def _run(args: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                          creationflags=NO_WINDOW, errors="replace")


def _first_error(text: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line and ("error" in line.lower() or "can't" in line.lower() or "cannot" in line.lower()
                     or "no supported database" in line.lower()):
            return re.sub(r"^(LibClamAV )?(ERROR|Error):\s*", "", line)
    return next((l.strip() for l in text.splitlines() if l.strip()), "")


class ClamAV:
    def __init__(self, events):
        self.events = events
        self._lock = threading.Lock()
        self._status = {"state": "unchecked"}
        self._checking = False
        self._key = None                 # custom_dir the status was computed for
        self._last_error_log = 0.0

    # -- health check ------------------------------------------------------------ #

    def status(self, custom_dir: str = "") -> dict:
        """Cheap: returns the cached result and starts a background check when needed.
        The real check runs ClamAV once, which can take ~30 s without the clamd service."""
        with self._lock:
            if self._key != custom_dir and not self._checking:
                self._key, self._checking = custom_dir, True
                self._status = {**self._status, "state": "checking"}
                threading.Thread(target=self._check, args=(custom_dir,), daemon=True, name="clamav-check").start()
            return dict(self._status)

    def recheck(self, custom_dir: str = "") -> dict:
        with self._lock:
            self._key = None          # forces status() to start a new check
        return self.status(custom_dir)

    def _check(self, custom_dir: str):
        result = self._probe(custom_dir)
        with self._lock:
            self._status, self._checking = result, False
        if result["state"] == "error":
            self.events.add("warning", "clamav", f"ClamAV found but not working: {result['error']}")
        elif result["state"] == "ok":
            mode = "clamd service (fast)" if result["daemon"] else "clamscan batch pass"
            self.events.add("info", "clamav", f"ClamAV {result['version']} ready, definitions {result['db_date'] or 'loaded'}, using {mode}")

    def _probe(self, custom_dir: str) -> dict:
        loc = find(custom_dir)
        base = {"clamscan": loc["clamscan"], "clamdscan": loc["clamdscan"], "searched": loc["searched"],
                "daemon": False, "version": "", "db_version": "", "db_date": "", "error": "", "checked_at": time.time()}
        exe = loc["clamscan"] or loc["clamdscan"]
        if not exe:
            return {**base, "state": "not_found",
                    "error": "clamscan wasn't found on PATH or in the usual install folders"}

        # 1. Version line: "ClamAV 1.4.1/27432/Tue Oct 20 08:21:07 2026". Without virus
        #    definitions it's just "ClamAV 1.4.1".
        try:
            out = _run([exe, "--version"], 30)
        except (OSError, subprocess.TimeoutExpired) as e:
            return {**base, "state": "error", "error": f"Couldn't run {exe}: {e}"}
        line = (out.stdout or out.stderr).strip().splitlines()[0] if (out.stdout or out.stderr).strip() else ""
        parts = line.removeprefix("ClamAV ").split("/")
        base.update(version=parts[0], db_version=parts[1] if len(parts) > 1 else "",
                    db_date=parts[2] if len(parts) > 2 else "")

        # 2. Is the clamd service answering? (--ping exists in ClamAV 0.103.3+)
        if loc["clamdscan"]:
            try:
                base["daemon"] = _run([loc["clamdscan"], "--ping", "1"], 10).returncode == 0
            except (OSError, subprocess.TimeoutExpired):
                base["daemon"] = False

        # 3. Scan a tiny harmless file to prove the engine and its definitions load.
        probe_exe = loc["clamdscan"] if base["daemon"] else loc["clamscan"]
        if not probe_exe:
            return {**base, "state": "error",
                    "error": "Only clamdscan was found and the clamd service isn't running. Start clamd or install clamscan."}
        fd, probe = tempfile.mkstemp(prefix="sentinel-clamav-probe-", suffix=".txt")
        try:
            os.write(fd, b"Sentinel ClamAV health check. Harmless.\n")
            os.close(fd)
            res = _run([probe_exe, "--no-summary", probe], 180)
        except (OSError, subprocess.TimeoutExpired) as e:
            return {**base, "state": "error", "error": f"Test scan failed: {e}"}
        finally:
            try:
                os.unlink(probe)
            except OSError:
                pass
        if res.returncode == 2:
            msg = _first_error(res.stderr + "\n" + res.stdout)
            if "database" in msg.lower() or not base["db_version"]:
                msg = ("No virus definitions are installed. Run freshclam (ClamAV's updater) once to download them"
                       + (f". ClamAV said: {msg}" if msg else ""))
            return {**base, "state": "error", "error": msg}
        return {**base, "state": "ok"}

    # -- scanning ------------------------------------------------------------------- #

    def ready(self) -> bool:
        return self._status.get("state") == "ok"

    def fast(self) -> bool:
        """True when per-file scanning is cheap (clamd service answering)."""
        return self.ready() and self._status.get("daemon", False)

    def scan_file(self, path: str) -> tuple[str, str] | None:
        """Scan one file. Returns ("clamav", threat_name) or None. Uses clamd if available,
        otherwise clamscan (slow: only used for single files, e.g. real-time protection)."""
        st = self._status
        if st.get("state") != "ok":
            return None
        exe = st["clamdscan"] if st.get("daemon") else st["clamscan"]
        args = [exe, "--no-summary", path]
        if st.get("daemon") and not IS_WINDOWS:
            args.insert(1, "--fdpass")   # let clamd read files it has no permission for
        try:
            res = _run(args, 300)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if res.returncode == 1:
            for p, name in _parse_found(res.stdout):
                return ("clamav", name)
        elif res.returncode == 2:
            if st.get("daemon"):
                # The service went away: fall back to clamscan until the next re-check.
                self._status = {**st, "daemon": False}
            self._log_error(res.stderr or res.stdout)
        return None

    def scan_many(self, roots: list[str], max_mb: int, exclude_dirs: list[str], cancel: threading.Event,
                  on_progress=None):
        """One clamscan run over whole folders (loads the database once). Yields (path, threat)."""
        st = self._status
        if st.get("state") != "ok" or not st.get("clamscan"):
            return
        args = [st["clamscan"], "-r", "--no-summary", "--infected", "--stdout",
                f"--max-filesize={max_mb}M", f"--max-scansize={max_mb * 4}M"]
        for d in exclude_dirs:
            args.append(f"--exclude-dir=^{re.escape(d)}")
        args += roots
        try:
            proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                    errors="replace", creationflags=NO_WINDOW)
        except OSError as e:
            self._log_error(str(e))
            return
        threading.Thread(target=lambda: proc.stderr.read(), daemon=True).start()   # keep stderr from filling up
        try:
            for line in proc.stdout:
                if cancel.is_set():
                    proc.terminate()
                    break
                for path, name in _parse_found(line):
                    yield path, name
        finally:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()

    def _log_error(self, text: str):
        if time.time() - self._last_error_log > 600:   # at most one warning per 10 minutes
            self._last_error_log = time.time()
            self.events.add("warning", "clamav", f"ClamAV error: {_first_error(text) or 'unknown error'}")


def _parse_found(text: str):
    """Lines look like 'C:\\path\\file.exe: Win.Test.EICAR_HDB-1 FOUND'."""
    for line in text.splitlines():
        line = line.rstrip()
        if line.endswith(" FOUND"):
            path, _, name = line[: -len(" FOUND")].rpartition(": ")
            if path:
                yield path, name.strip()
