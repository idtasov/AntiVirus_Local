"""
Process monitor: behaviour-based checks on programs as they start.

Without a kernel driver we can't intercept a program *before* it runs, but we can
notice it within about a second of starting, judge it, and suspend it. Each new process is:

  1. Checked against behaviour rules (evaluate_process): what started it, where it runs
     from, and what its command line does. These catch "living off the land" attacks that
     use legitimate Windows tools and so never trip a file signature.
  2. Its executable is scanned with the normal file engines (scan on launch).

Requires psutil (`py -m pip install psutil`). Without it, Sentinel runs and this
feature reports itself as unavailable.
"""

from __future__ import annotations

import os
import re
import threading
import time
from pathlib import Path

try:
    import psutil
except ImportError:  # optional dependency
    psutil = None

IS_WINDOWS = os.name == "nt"

# Apps that open documents/web content from the internet. When one of them starts a shell
# or script host, it usually means a malicious document or exploit is running code.
DOCUMENT_APPS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
                 "mspub.exe", "onenote.exe", "visio.exe", "acrord32.exe", "acrobat.exe",
                 "foxitpdfreader.exe", "foxitreader.exe", "sumatrapdf.exe", "wordpad.exe"}
SHELLS_AND_SCRIPT_HOSTS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
                           "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
                           "bitsadmin.exe", "msbuild.exe", "installutil.exe", "wmic.exe"}

# Core Windows processes and where they must live. A copy running from anywhere else is
# a classic disguise ("svchost.exe" in AppData).
SYSTEM_PROCESS_HOMES = {
    "svchost.exe": ("\\windows\\system32\\", "\\windows\\syswow64\\"),
    "lsass.exe": ("\\windows\\system32\\",),
    "csrss.exe": ("\\windows\\system32\\",),
    "winlogon.exe": ("\\windows\\system32\\",),
    "services.exe": ("\\windows\\system32\\",),
    "smss.exe": ("\\windows\\system32\\",),
    "wininit.exe": ("\\windows\\system32\\",),
    "spoolsv.exe": ("\\windows\\system32\\",),
    "taskhostw.exe": ("\\windows\\system32\\",),
    "explorer.exe": ("\\windows\\",),
}

# Processes that must never be suspended or killed: doing so freezes or crashes Windows.
CRITICAL_PROCESSES = {"system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
                      "services.exe", "lsass.exe", "lsaiso.exe", "memory compression",
                      "systemd", "init", "launchd", "kernel_task"}

# Well-known abuse patterns of built-in Windows tools (downloading or running remote code).
LOLBIN_PATTERNS = [
    (re.compile(r"mshta(\.exe)?\W.*(https?:|javascript:|vbscript:)"), "mshta running remote or inline script"),
    (re.compile(r"certutil(\.exe)?\W.*-urlcache"), "certutil used to download a file"),
    (re.compile(r"certutil(\.exe)?\W.*-decode"), "certutil used to decode a hidden file"),
    (re.compile(r"regsvr32(\.exe)?\W.*/i:\s*https?:"), "regsvr32 loading a remote script"),
    (re.compile(r"rundll32(\.exe)?\W.*javascript:"), "rundll32 running inline JavaScript"),
    (re.compile(r"bitsadmin(\.exe)?\W.*/transfer"), "bitsadmin used to download a file"),
]
ENCODED_PS = re.compile(r"(powershell|pwsh)(\.exe)?\b.*\s-(e|en|enc|encodedcommand)\s")
HIDDEN_PS = re.compile(r"(powershell|pwsh)(\.exe)?\b.*\s-(w|windowstyle)\s+hidden")
DOWNLOAD_RUN = re.compile(r"(iex|invoke-expression).{0,200}(downloadstring|invoke-webrequest|iwr\s|irm\s)"
                          r"|(downloadstring|invoke-webrequest|iwr\s|irm\s).{0,200}\|\s*(iex|invoke-expression)")

THRESHOLDS = {"low": 75, "medium": 50, "high": 35}


def _user_writable_dirs() -> list[str]:
    """Folders any program can write to, where malware typically drops and runs payloads."""
    dirs = []
    if IS_WINDOWS:
        for var in ("TEMP", "TMP"):
            if os.environ.get(var):
                dirs.append(os.environ[var])
        home = os.path.expanduser("~")
        dirs += [os.path.join(home, "Downloads"), os.path.join(os.environ.get("PUBLIC", r"C:\Users\Public")),
                 os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "$Recycle.Bin")]
    else:
        dirs += ["/tmp", "/var/tmp", "/dev/shm"]
    return [os.path.normcase(os.path.abspath(d)) + os.sep for d in dirs]


WRITABLE_DIRS = _user_writable_dirs()


def evaluate_process(info: dict, windows: bool = IS_WINDOWS, writable_dirs: list[str] | None = None) -> tuple[int, list[str]]:
    """
    Score one process from a plain dict: name, exe, cmdline (string), parent_name.
    Pure function (no OS calls), so the rules can be tested anywhere.
    """
    score, reasons = 0, []

    def flag(points: int, reason: str):
        nonlocal score
        score += points
        reasons.append(f"{reason} (+{points})")

    name = (info.get("name") or "").lower()
    exe = (info.get("exe") or "").lower()
    cmd = (info.get("cmdline") or "").lower()
    parent = (info.get("parent_name") or "").lower()
    dirs = WRITABLE_DIRS if writable_dirs is None else writable_dirs

    if windows:
        if parent in DOCUMENT_APPS and name in SHELLS_AND_SCRIPT_HOSTS:
            flag(60, f"{info.get('parent_name')} started {info.get('name')}: documents shouldn't launch shells or script hosts")
        homes = SYSTEM_PROCESS_HOMES.get(name)
        if homes and exe and not any(h in exe for h in homes):
            flag(70, f"Named like the Windows process {info.get('name')} but runs from {info.get('exe')}")
        if ENCODED_PS.search(cmd):
            flag(50, "PowerShell started with an encoded (hidden) command")
        if HIDDEN_PS.search(cmd):
            flag(15, "PowerShell started with a hidden window")
        if DOWNLOAD_RUN.search(cmd):
            flag(55, "Downloads code from the internet and runs it immediately")
        for pattern, why in LOLBIN_PATTERNS:
            if pattern.search(cmd):
                flag(55, f"Built-in Windows tool misused: {why}")
                break

    # Cross-platform: programs running straight out of temp/download folders. Installers do
    # this too, so on its own it only reaches the "high" sensitivity threshold.
    if exe and any(os.path.normcase(exe).startswith(d.lower()) for d in dirs):
        flag(35, f"Runs from a temporary or download folder: {info.get('exe')}")

    return score, reasons


class ProcessMonitor(threading.Thread):
    """Polls the process list, evaluates new processes, and keeps alerts for the dashboard."""

    def __init__(self, engine):
        super().__init__(daemon=True, name="procmon")
        self.engine = engine
        self.stop_event = threading.Event()
        self.seen: set[tuple[int, float]] = set()   # (pid, create_time): pids get reused
        self.verdicts: dict[tuple[int, float], dict] = {}
        self.exe_cache: dict[tuple, dict | None] = {}  # (exe, mtime, size) -> detection
        self.my_pid = os.getpid()

    @staticmethod
    def available() -> bool:
        return psutil is not None

    # -- polling ----------------------------------------------------------------- #

    def run(self):
        if not self.available():
            return
        first = True
        while not self.stop_event.is_set():
            cfg = self.engine.config.snapshot()
            if cfg["process_monitor_enabled"]:
                self._poll(cfg, baseline=first)
                first = False
            else:
                first = True  # re-baseline when switched back on, so old processes aren't flagged en masse
            self.stop_event.wait(cfg["process_interval_sec"])

    def _info(self, proc) -> dict | None:
        try:
            with proc.oneshot():
                info = {"pid": proc.pid, "name": proc.name(), "create_time": proc.create_time()}
                for key, getter in (("exe", proc.exe), ("username", proc.username),
                                    ("cmdline", lambda: " ".join(proc.cmdline())), ("ppid", proc.ppid)):
                    try:
                        info[key] = getter()
                    except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                        info[key] = ""   # other users'/system processes hide some details
                try:
                    info["parent_name"] = psutil.Process(info["ppid"]).name() if info["ppid"] else ""
                except (psutil.Error, OSError, TypeError):
                    info["parent_name"] = ""
                return info
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None

    def _poll(self, cfg: dict, baseline: bool):
        current = set()
        for proc in psutil.process_iter():
            try:
                key = (proc.pid, proc.create_time())
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            current.add(key)
            if key in self.seen:
                continue
            self.seen.add(key)
            if baseline or proc.pid == self.my_pid:
                continue   # processes already running when monitoring started aren't "new"
            info = self._info(proc)
            if info:
                self._judge(info, cfg)
        # Forget processes that have exited.
        self.seen &= current
        self.verdicts = {k: v for k, v in self.verdicts.items() if k in current}

    def _allowlisted(self, info: dict, cfg: dict) -> bool:
        allowed = {a.lower() for a in cfg["allowlist_processes"]}
        return (info.get("exe") or "").lower() in allowed or (info.get("name") or "").lower() in allowed

    def _judge(self, info: dict, cfg: dict):
        if self._allowlisted(info, cfg):
            return
        score, reasons = evaluate_process(info)
        detection = self._scan_exe(info.get("exe"), cfg) if cfg["process_scan_executables"] else None
        if detection:
            score += 100
            reasons.insert(0, f"Executable flagged by file scan: {detection['threat']} (+100)")
        if score < THRESHOLDS[cfg["heuristic_sensitivity"]]:
            return

        action = "alerted"
        if cfg["process_action"] == "suspend" and not self.is_critical(info):
            ok, _ = self.control(info["pid"], info["create_time"], "suspend", source="auto")
            action = "suspended" if ok else "alerted (suspend failed)"
        alert = {**info, "score": score, "reasons": reasons, "action": action, "ts": time.time()}
        self.verdicts[(info["pid"], info["create_time"])] = alert
        self.engine.add_process_alert(alert)

    def _scan_exe(self, exe: str, cfg: dict) -> dict | None:
        """Scan a newly started program's file, caching by (path, mtime, size) so a program
        launched 100 times isn't read 100 times."""
        if not exe:
            return None
        try:
            st = os.stat(exe)
        except OSError:
            return None
        key = (exe, st.st_mtime_ns, st.st_size)
        if key not in self.exe_cache:
            scanner = self.engine.scanner
            prepared = scanner.prepare(cfg)   # ClamAV only if clamd makes it fast: launches must not wait
            self.exe_cache[key] = (None if scanner.is_excluded(exe, prepared)
                                   else scanner.scan_file(Path(exe), prepared))
            if len(self.exe_cache) > 5000:
                self.exe_cache.clear()
        return self.exe_cache[key]

    # -- listing & control ------------------------------------------------------ #

    @staticmethod
    def is_critical(info: dict) -> bool:
        return (info.get("name") or "").lower() in CRITICAL_PROCESSES or info.get("pid") in (0, 4)

    def list_processes(self) -> list[dict]:
        out = []
        for proc in psutil.process_iter(["pid", "name", "exe", "username", "create_time", "status", "memory_info"]):
            i = proc.info
            mem = i.get("memory_info")
            verdict = self.verdicts.get((i["pid"], i.get("create_time")))
            out.append({
                "pid": i["pid"], "name": i.get("name") or "", "exe": i.get("exe") or "",
                "username": i.get("username") or "", "create_time": i.get("create_time"),
                "status": i.get("status") or "", "rss": mem.rss if mem else 0,
                "score": verdict["score"] if verdict else 0,
                "reasons": verdict["reasons"] if verdict else [],
                "critical": self.is_critical(i), "self": i["pid"] == self.my_pid,
            })
        out.sort(key=lambda p: (-p["score"], -(p["create_time"] or 0)))
        return out

    def control(self, pid: int, create_time: float, action: str, source: str = "manual") -> tuple[bool, str]:
        """Suspend, resume or terminate one process. create_time guards against PID reuse:
        if the original process exited and its PID was recycled, we refuse."""
        if not self.available():
            return False, "psutil is not installed"
        try:
            proc = psutil.Process(pid)
            if abs(proc.create_time() - float(create_time)) > 0.01:
                return False, "That process has already exited"
            name = proc.name()
            if pid == self.my_pid:
                return False, "That's Sentinel itself"
            if self.is_critical({"name": name, "pid": pid}):
                done = {"suspend": "suspended", "resume": "resumed", "terminate": "terminated"}.get(action, action)
                return False, f"{name} is critical to the system and can't be {done}"
            {"suspend": proc.suspend, "resume": proc.resume, "terminate": proc.terminate}[action]()
        except KeyError:
            return False, "Unknown action"
        except psutil.NoSuchProcess:
            return False, "That process has already exited"
        except psutil.AccessDenied:
            return False, "Access denied: run Sentinel as administrator to control this process"
        verb = {"suspend": "Suspended", "resume": "Resumed", "terminate": "Terminated"}[action]
        self.engine.events.add("warning" if action != "resume" else "info", "process",
                               f"{verb} {name} (PID {pid}) [{source}]")
        for key, alert in self.verdicts.items():
            if key[0] == pid:
                alert["action"] = verb.lower()
        return True, f"{verb} {name}"
