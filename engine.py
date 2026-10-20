"""
Sentinel engine: the detection, quarantine and monitoring core.

Everything runs locally. Nothing is uploaded anywhere (no cloud lookups, no
telemetry). The web UI in sentinel.py is a thin layer over the Engine class.

How a single file is judged (see Scanner.scan_file):
    1. Exclusions    - skip paths / extensions / hashes you trust
    2. Hash check    - SHA-256 against known-bad lists in signatures/*.hashes
    3. Pattern rules - byte strings from signatures/patterns.json
    4. Heuristics    - score-based checks for suspicious traits
    5. Archives      - steps 2-4 applied to each member of a .zip
    6. ClamAV        - optional second opinion, if installed and enabled
The first engine that flags the file produces a "detection" dict.
"""

from __future__ import annotations

import hashlib
import io
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile
from collections import Counter, deque
from pathlib import Path

# Bump together with UI_VERSION in static/index.html whenever the API changes. The dashboard
# compares the two and asks you to restart Sentinel if the page is newer than the running server.
VERSION = 4

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"          # config, logs, state, quarantine
SIG_DIR = BASE_DIR / "signatures"     # user-editable detection rules
QUAR_DIR = DATA_DIR / "quarantine"

HOME = Path.home()
TEMP = Path(tempfile.gettempdir())

# Pseudo-filesystems that are never walked: they aren't real files and some are endless.
SKIP_ROOTS = ("/proc", "/sys", "/dev", "/run")


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

DEFAULT_CONFIG = {
    # Real-time protection: watch these folders and scan new/changed files.
    "realtime_enabled": True,
    "realtime_paths": [str(HOME / "Downloads"), str(HOME / "Desktop")],
    "realtime_interval_sec": 3,

    # Detection engines
    "heuristics_enabled": True,
    "heuristic_sensitivity": "medium",      # low | medium | high
    "scan_archives": True,
    "use_clamav": False,
    "max_file_size_mb": 100,                # larger files are skipped

    # What to do when something is found
    "action_on_detect": "quarantine",       # quarantine | report
    # In OS/program folders, only exact hash matches are auto-quarantined; heuristic
    # hits there are just reported, so a false positive can't break Windows or an app.
    "protect_system_files": True,

    # Scan locations
    "quick_scan_paths": [str(HOME / "Downloads"), str(HOME / "Desktop"), str(TEMP)],
    "full_scan_paths": [str(HOME)],

    # Exclusions (Sentinel's own folder is always excluded as well)
    "exclude_paths": [],
    "exclude_extensions": [".iso", ".vmdk", ".qcow2"],
    "allowlist_hashes": [],

    # Scheduled scans
    "scheduled_scan_enabled": False,
    "scheduled_scan_type": "quick",         # quick | full | computer
    "scheduled_interval_hours": 24,
}

# Allowed values for string settings, and min/max for numeric ones.
CHOICES = {
    "heuristic_sensitivity": {"low", "medium", "high"},
    "action_on_detect": {"quarantine", "report"},
    "scheduled_scan_type": {"quick", "full", "computer"},
}
LIMITS = {
    "realtime_interval_sec": (1, 300),
    "max_file_size_mb": (1, 2048),
    "scheduled_interval_hours": (1, 24 * 30),
}


class Config:
    """JSON-backed settings. Every update is validated against DEFAULT_CONFIG."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._data = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
        if path.exists():
            try:
                self._data.update(self._validate(json.loads(path.read_text())))
            except (OSError, ValueError):
                pass  # corrupt file: fall back to defaults, it will be rewritten below
        self._save()

    def snapshot(self) -> dict:
        """Return a deep copy so callers can't mutate live settings by accident."""
        with self._lock:
            return json.loads(json.dumps(self._data))

    def update(self, changes: dict) -> dict:
        clean = self._validate(changes)
        with self._lock:
            self._data.update(clean)
            self._save()
        return self.snapshot()

    def _save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data, indent=2))
        tmp.replace(self.path)  # atomic rename, so a crash never leaves half a file

    @staticmethod
    def _validate(changes: dict) -> dict:
        """Keep only known keys whose value has the right type; clamp numbers."""
        clean = {}
        for key, value in (changes or {}).items():
            if key not in DEFAULT_CONFIG:
                continue
            default = DEFAULT_CONFIG[key]
            if isinstance(default, bool):          # must be checked before int (bool is an int)
                if isinstance(value, bool):
                    clean[key] = value
            elif isinstance(default, int):
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    lo, hi = LIMITS.get(key, (0, 10**9))
                    clean[key] = int(min(max(value, lo), hi))
            elif isinstance(default, str):
                if isinstance(value, str) and value in CHOICES.get(key, {value}):
                    clean[key] = value
            elif isinstance(default, list):
                if isinstance(value, list) and all(isinstance(v, str) for v in value):
                    clean[key] = [v.strip() for v in value if v.strip()]
        return clean


# --------------------------------------------------------------------------- #
# Event log
# --------------------------------------------------------------------------- #

class EventLog:
    """Append-only JSON-lines log, plus an in-memory ring buffer for the UI."""

    def __init__(self, path: Path, keep: int = 1000):
        self.path = path
        self.recent: deque = deque(maxlen=keep)
        self._lock = threading.Lock()
        if path.exists():
            # Only the tail is needed for the UI; the full history stays on disk.
            for line in path.read_text(errors="ignore").splitlines()[-keep:]:
                try:
                    self.recent.append(json.loads(line))
                except ValueError:
                    pass

    def add(self, level: str, kind: str, message: str, **extra):
        """level: info | warning | threat. kind: scan | detection | config | quarantine | realtime ..."""
        event = {"ts": time.time(), "level": level, "kind": kind, "message": message, **extra}
        with self._lock:
            self.recent.append(event)
            with open(self.path, "a") as f:
                f.write(json.dumps(event) + "\n")

    def list(self, limit: int = 200) -> list:
        with self._lock:
            return list(reversed(self.recent))[:limit]


# --------------------------------------------------------------------------- #
# Signatures (hash lists + byte-pattern rules)
# --------------------------------------------------------------------------- #

class Signatures:
    """
    Loads user-editable detection rules from signatures/:

      *.hashes       one SHA-256 per line, optionally followed by a threat name:
                         <sha256>  Some.Threat.Name     # comments allowed
      patterns.json  list of rules:
                         {"name": "...", "strings": ["text", ...], "hex": ["deadbeef", ...],
                          "match": "any" | "all"}

    Drop in hash feeds you trust (e.g. exported from your own threat-intel) and
    press "Reload signatures" in the UI. No restart needed.
    """

    def __init__(self):
        self.hashes: dict[str, str] = {}
        self.patterns: list[dict] = []
        self.loaded_at = 0.0
        self.load()

    def load(self):
        hashes: dict[str, str] = {}
        for f in sorted(SIG_DIR.glob("*.hashes")):
            for line in f.read_text(errors="ignore").splitlines():
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split(None, 1)
                digest = parts[0].lower()
                if re.fullmatch(r"[0-9a-f]{64}", digest):
                    hashes[digest] = parts[1].strip() if len(parts) > 1 else f"HashMatch.{f.stem}"

        patterns: list[dict] = []
        pfile = SIG_DIR / "patterns.json"
        if pfile.exists():
            try:
                raw = json.loads(pfile.read_text())
            except ValueError:
                raw = []
            for rule in raw if isinstance(raw, list) else []:
                needles = [s.encode() for s in rule.get("strings", []) if isinstance(s, str) and s]
                for h in rule.get("hex", []):
                    try:
                        needles.append(bytes.fromhex(h))
                    except (ValueError, TypeError):
                        pass
                if needles:
                    patterns.append({
                        "name": str(rule.get("name", "Unnamed.Rule")),
                        "needles": needles,
                        "match": "all" if rule.get("match") == "all" else "any",
                    })

        # Swap both at once so a scan running concurrently never sees a half-loaded set.
        self.hashes, self.patterns = hashes, patterns
        self.loaded_at = time.time()

    def match_hash(self, sha256: str) -> str | None:
        return self.hashes.get(sha256)

    def match_patterns(self, data: bytes) -> str | None:
        for rule in self.patterns:
            hits = [n in data for n in rule["needles"]]
            if all(hits) if rule["match"] == "all" else any(hits):
                return rule["name"]
        return None


# --------------------------------------------------------------------------- #
# Heuristics
# --------------------------------------------------------------------------- #
# Each check adds points; if the total reaches the threshold for the chosen
# sensitivity, the file is flagged. Higher sensitivity catches more but also
# produces more false positives.

THRESHOLDS = {"low": 75, "medium": 50, "high": 35}

EXECUTABLE_EXTS = {".exe", ".dll", ".scr", ".com", ".pif", ".bat", ".cmd", ".msi", ".vbs",
                   ".vbe", ".js", ".jse", ".wsf", ".ps1", ".hta", ".jar", ".lnk", ".sh",
                   ".apk", ".app", ".elf"}
DECOY_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf",
              ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".mov", ".zip", ".csv"}
SCRIPT_EXTS = {".js", ".mjs", ".cjs", ".jse", ".vbs", ".vbe", ".ps1", ".bat", ".cmd", ".sh", ".hta",
               ".wsf", ".py", ".html", ".htm"}
OFFICE_EXTS = {".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm"}
EXEC_KINDS = {"PE", "ELF", "Mach-O"}

# Obfuscated-script indicators. Big minified web libraries legitimately contain base64 data,
# regex `.exec(` calls and XMLHttpRequest, so merely seeing "decode" and "execute" words
# somewhere in a file proves nothing. The strong rules below therefore require decoded or
# downloaded content to be fed *directly* into an execution call within one statement,
# e.g. eval(atob("...")), iex(...FromBase64String...), "... | base64 -d | sh".
# Patterns run on lower-cased text.
B64_BLOB = re.compile(rb"[A-Za-z0-9+/]{600,}={0,2}")
_DECODE = rb"(?:atob\s*\(|frombase64string|b64decode|base64\s+(?:-d|--decode)\b|unescape\s*\()"
# Lookbehinds skip method calls and longer identifiers: `/re/.exec(s)`, `regexec(`, `$.eval(`.
_EXEC = rb"(?:(?<![\w.$])eval|(?<![\w.$])exec|invoke-expression|(?<![\w.$-])iex|new\s+function)"
_FETCH = rb"(?:downloadstring|downloadfile|invoke-webrequest|invoke-restmethod|(?<![\w.$-])iwr|(?<![\w.$-])irm)"
_STMT = rb"[^;\n]{0,300}?"   # "within the same statement": no ; or newline in between

DECODE_THEN_RUN = re.compile(
    _EXEC + rb"\s*\(?" + _STMT + _DECODE                                   # eval(atob(x))
    + rb"|" + _DECODE + _STMT + rb"\|\s*(?:iex|invoke-expression|sh|bash)\b")  # ... | iex
FETCH_THEN_RUN = re.compile(
    _EXEC + rb"\s*\(?" + _STMT + _FETCH                                    # iex (...).downloadstring(url)
    + rb"|" + _FETCH + _STMT + rb"\|\s*(?:iex|invoke-expression)\b"        # iwr url | iex
    + rb"|(?:curl|wget)\s[^;\n|]{0,300}\|\s*(?:sudo\s+)?(?:sh|bash)\b")     # curl url | sh
# Weaker, statement-independent versions: only used for non-web scripts (PowerShell, VBS,
# batch...), where splitting decode and execute across lines is common and libraries are rare.
LOOSE_DECODE = re.compile(_DECODE)
LOOSE_EXEC = re.compile(_EXEC + rb"\s*[(\s]")
WEB_EXTS = {".js", ".mjs", ".cjs", ".html", ".htm"}
ENCODED_PS = re.compile(rb"powershell[^\n]{0,80}\s-(e|en|enc|encodedcommand)\s", re.I)


def has_raw_base64_blob(data: bytes) -> bool:
    """A long base64 run that isn't a data: URI. Web files embed fonts, images and source
    maps as `data:...;base64,<blob>`, which is normal and not a sign of hidden code."""
    for m in B64_BLOB.finditer(data):
        if b"base64," not in data[max(0, m.start() - 20):m.start()]:
            return True
    return False

SAMPLE = 2 * 1024 * 1024  # only the first 2 MB are used for content heuristics (speed)


def file_kind(data: bytes) -> str | None:
    """Identify the real file type from its first bytes ("magic numbers"), ignoring the name."""
    if data[:2] == b"MZ":
        return "PE"                       # Windows executable / DLL
    if data[:4] == b"\x7fELF":
        return "ELF"                      # Linux executable
    if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"):
        return "Mach-O"                   # macOS executable
    if data[:4] == b"PK\x03\x04":
        return "ZIP"                      # also .docx/.xlsx/.jar/.apk
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "OLE"                      # legacy Office (.doc/.xls)
    return None


def shannon_entropy(data: bytes) -> float:
    """Bits of randomness per byte (0-8). Compressed or encrypted data is close to 8."""
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def analyze(path: Path, data: bytes) -> tuple[int, list[str]]:
    """Return (score, reasons) for one file. Pure function: no I/O, easy to test."""
    score = 0
    reasons: list[str] = []

    def flag(points: int, reason: str):
        nonlocal score
        score += points
        reasons.append(f"{reason} (+{points})")

    name = path.name
    suffixes = [s.strip().lower() for s in Path(name.lower()).suffixes]
    ext = suffixes[-1] if suffixes else ""
    kind = file_kind(data)
    head = data[:SAMPLE]

    # 1. Filename tricks that hide the real file type from the user.
    if "‮" in name:
        flag(50, "Filename contains a right-to-left override character that hides the real extension")
    if len(suffixes) >= 2 and ext in EXECUTABLE_EXTS and suffixes[-2] in DECOY_EXTS:
        flag(55, f"Double extension: looks like '{suffixes[-2]}' but is really '{ext}'")
    if re.search(r"\s{5,}\.\w+$", name):
        flag(15, "Long run of spaces before the extension pushes it out of view")

    # 2. Content doesn't match the name: an executable pretending to be a document/image.
    if kind in EXEC_KINDS and ext in DECOY_EXTS:
        flag(50, f"{kind} executable disguised with a '{ext}' extension")

    # 3. Packed / encrypted executables: very high entropy is a classic packer trait.
    if kind in EXEC_KINDS:
        ent = shannon_entropy(head)
        if ent > 7.2:
            flag(30, f"Executable has very high entropy ({ent:.2f}/8), typical of packing or encryption")

    # 4. Obfuscated scripts: hidden or downloaded content fed straight into execution.
    is_text = b"\x00" not in head[:4096]
    if is_text and (ext in SCRIPT_EXTS or ext == ""):
        low = head.lower()
        if has_raw_base64_blob(head):
            flag(15, "Contains a very long base64-encoded blob")
        if DECODE_THEN_RUN.search(low):
            flag(35, "Decodes hidden content and immediately executes it")
        elif ext not in WEB_EXTS and LOOSE_DECODE.search(low) and LOOSE_EXEC.search(low):
            flag(35, "Decodes hidden content and also executes code dynamically")
        if ENCODED_PS.search(head):
            flag(35, "Launches PowerShell with an encoded command")
        if FETCH_THEN_RUN.search(low):
            flag(20, "Downloads remote code and executes it")

    # 5. Office macros: a common delivery vector, though plenty of legit files use them too.
    if kind == "ZIP" and ext in OFFICE_EXTS:
        try:
            names = [n.lower() for n in zipfile.ZipFile(io.BytesIO(data)).namelist()]
            if any(n.endswith("vbaproject.bin") for n in names):
                flag(25, "Office document contains VBA macros")
        except zipfile.BadZipFile:
            pass
    elif kind == "OLE" and b"_VBA_PROJECT" in data:
        flag(25, "Office document contains VBA macros")

    # 6. Hidden executables dropped in temp or download folders.
    if name.startswith(".") and kind in EXEC_KINDS:
        parent = str(path.parent)
        if parent.startswith(str(TEMP)) or parent.startswith(str(HOME / "Downloads")):
            flag(20, "Hidden executable in a temp/download folder")

    return score, reasons


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #

def clamav_binary() -> str | None:
    """Prefer clamdscan (talks to the running daemon, fast) over clamscan (reloads DB per call)."""
    return shutil.which("clamdscan") or shutil.which("clamscan")


def _under(path: str, roots: list[str]) -> bool:
    """True if `path` equals or lives inside one of `roots` (roots must already be normcased)."""
    path = os.path.normcase(path)
    return any(path == r or path.startswith(r.rstrip(os.sep) + os.sep) for r in roots)


def _norm(p: str) -> str:
    return os.path.abspath(os.path.expanduser(p))


def _norm_root(p: str) -> str:
    """Normalise an exclusion root for comparison. normcase lower-cases paths and turns
    '/' into '\\' on Windows (whose filesystem is case-insensitive) and is a no-op elsewhere."""
    return os.path.normcase(_norm(p))


def computer_roots() -> list[str]:
    """Roots for a whole-computer scan: every local fixed drive on Windows (C:\\, D:\\ ...),
    or / elsewhere. Network, CD and RAM drives are left out: they're slow, or not this computer."""
    if os.name != "nt":
        return ["/"]
    import ctypes
    import string
    DRIVE_FIXED = 3
    drives = [f"{c}:\\" for c in string.ascii_uppercase
              if ctypes.windll.kernel32.GetDriveTypeW(f"{c}:\\") == DRIVE_FIXED]
    return drives or [os.environ.get("SystemDrive", "C:") + "\\"]


def _system_roots() -> tuple[list[str], list[str]]:
    """(protected OS/program folders, writable exceptions inside them)."""
    if os.name == "nt":
        env = os.environ
        windir = env.get("SystemRoot", r"C:\Windows")
        roots = [windir, env.get("ProgramFiles", r"C:\Program Files"),
                 env.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                 os.path.join(env.get("ProgramData", r"C:\ProgramData"), "Microsoft")]
        # Temp folders are writable by programs and a favourite drop spot for malware,
        # so detections there are quarantined normally.
        exceptions = [os.path.join(windir, "Temp")]
    elif sys.platform == "darwin":
        roots = ["/System", "/Library", "/Applications", "/usr", "/bin", "/sbin", "/private/etc"]
        exceptions = []
    else:
        roots = ["/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/etc", "/boot", "/opt", "/snap", "/var/lib"]
        exceptions = []
    return [_norm_root(r) for r in roots], [_norm_root(e) for e in exceptions]


SYSTEM_ROOTS, SYSTEM_EXCEPTIONS = _system_roots()


def is_system_path(path: str) -> bool:
    return _under(path, SYSTEM_ROOTS) and not _under(path, SYSTEM_EXCEPTIONS)


class Scanner:
    def __init__(self, signatures: Signatures):
        self.signatures = signatures

    @staticmethod
    def prepare(cfg: dict) -> dict:
        """Pre-compute normalised exclusion lists once per scan instead of once per file."""
        cfg = dict(cfg)
        cfg["_excl_roots"] = [_norm_root(p) for p in (str(BASE_DIR), *SKIP_ROOTS, *cfg["exclude_paths"])]
        cfg["_excl_exts"] = {("." + e.lower().lstrip(".")) for e in cfg["exclude_extensions"]}
        cfg["_allow"] = {h.lower() for h in cfg["allowlist_hashes"]}
        cfg["_max_bytes"] = cfg["max_file_size_mb"] * 1024 * 1024
        cfg["_threshold"] = THRESHOLDS[cfg["heuristic_sensitivity"]]
        return cfg

    def is_excluded(self, path: str, cfg: dict) -> bool:
        if _under(path, cfg["_excl_roots"]):
            return True
        return os.path.splitext(path)[1].lower() in cfg["_excl_exts"]

    def iter_files(self, roots: list[str], cfg: dict, cancel: threading.Event | None = None):
        """Yield every non-excluded regular file under `roots`, without following symlinks."""
        for root in roots:
            root = _norm(root)
            if os.path.isfile(root):
                if not self.is_excluded(root, cfg):
                    yield root
                continue
            for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
                if cancel is not None and cancel.is_set():
                    return
                # Prune excluded folders in place so os.walk never descends into them.
                dirnames[:] = [d for d in dirnames
                               if not _under(os.path.join(dirpath, d), cfg["_excl_roots"])]
                for fn in filenames:
                    full = os.path.join(dirpath, fn)
                    if not self.is_excluded(full, cfg):
                        yield full

    def scan_file(self, path: Path, cfg: dict) -> dict | None:
        """Scan one file. Returns a detection dict, or None if clean/unreadable/skipped."""
        try:
            if path.is_symlink() or not path.is_file():
                return None
            if path.stat().st_size > cfg["_max_bytes"]:
                return None
            data = path.read_bytes()
        except OSError:
            return None  # permission denied, vanished mid-scan, etc.

        sha = hashlib.sha256(data).hexdigest()
        if sha in cfg["_allow"]:
            return None

        hit = self._inspect(path, data, sha, cfg)
        if hit is None and cfg["scan_archives"] and data[:4] == b"PK\x03\x04":
            hit = self._scan_zip(data, cfg)
        if hit is None and cfg["use_clamav"]:
            hit = self._clamav(path)
        if hit is None:
            return None

        engine, threat, score, reasons = hit
        return {
            "id": uuid.uuid4().hex[:12],
            "ts": time.time(),
            "path": str(path),
            "sha256": sha,
            "size": len(data),
            "engine": engine,
            "threat": threat,
            "score": score,
            "reasons": reasons,
        }

    def _inspect(self, path: Path, data: bytes, sha: str, cfg: dict):
        """Run hash, pattern and heuristic engines on in-memory bytes."""
        name = self.signatures.match_hash(sha)
        if name:
            return ("signature", name, None, ["SHA-256 matches a known-bad hash"])
        name = self.signatures.match_patterns(data)
        if name:
            return ("pattern", name, None, ["Matched a byte-pattern rule"])
        if cfg["heuristics_enabled"]:
            score, reasons = analyze(path, data)
            if score >= cfg["_threshold"]:
                return ("heuristic", "Heuristic.Suspicious", score, reasons)
        return None

    def _scan_zip(self, data: bytes, cfg: dict):
        """Inspect members of a zip archive, with limits that defuse zip bombs."""
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            return None
        budget = cfg["_max_bytes"] * 4          # total uncompressed bytes we're willing to read
        for info in zf.infolist()[:1000]:
            if info.is_dir() or info.flag_bits & 0x1:   # skip folders and encrypted members
                continue
            if info.file_size > cfg["_max_bytes"] or info.file_size > budget:
                continue
            budget -= info.file_size
            try:
                member = zf.read(info)
            except Exception:  # corrupt member, unsupported compression, ...
                continue
            hit = self._inspect(Path(info.filename), member, hashlib.sha256(member).hexdigest(), cfg)
            if hit:
                engine, threat, score, reasons = hit
                return (engine, threat, score, [f"Inside archive: {info.filename}", *reasons])
        return None

    def _clamav(self, path: Path):
        exe = clamav_binary()
        if not exe:
            return None
        try:
            out = subprocess.run([exe, "--no-summary", "--stdout", str(path)],
                                 capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if out.returncode == 1:  # 1 = virus found, 0 = clean, 2 = error
            for line in out.stdout.splitlines():
                if line.endswith(" FOUND"):
                    name = line.rsplit(":", 1)[-1].removesuffix(" FOUND").strip()
                    return ("clamav", name, None, ["Flagged by ClamAV"])
        return None


# --------------------------------------------------------------------------- #
# Quarantine
# --------------------------------------------------------------------------- #

QUAR_KEY = b"sentinel-quarantine-v1"


def xor_bytes(data: bytes, key: bytes = QUAR_KEY) -> bytes:
    """
    XOR with a repeating key. This is NOT encryption, it just neutralises the file:
    it can't be executed, opened by mistake, or re-detected by other scanners.
    Uses big-integer maths because a Python byte-by-byte loop is ~100x slower.
    """
    if not data:
        return data
    stream = (key * (len(data) // len(key) + 1))[:len(data)]
    x = int.from_bytes(data, "big") ^ int.from_bytes(stream, "big")
    return x.to_bytes(len(data), "big")


class Quarantine:
    def __init__(self, events: EventLog):
        self.events = events
        self.index_path = DATA_DIR / "quarantine.json"
        self._lock = threading.Lock()
        try:
            self.entries: dict = json.loads(self.index_path.read_text())
        except (OSError, ValueError):
            self.entries = {}

    def _save(self):
        self.index_path.write_text(json.dumps(self.entries, indent=2))

    def list(self) -> list:
        with self._lock:
            return sorted(self.entries.values(), key=lambda e: e["ts"], reverse=True)

    def __len__(self):
        return len(self.entries)

    def isolate(self, path: Path, detection: dict) -> dict | None:
        """Move a file into the vault. The original is only removed after the copy is safely on disk."""
        try:
            data = path.read_bytes()
            mode = path.stat().st_mode
        except OSError as e:
            self.events.add("warning", "quarantine", f"Could not read {path}: {e}")
            return None

        qid = uuid.uuid4().hex[:12]
        qfile = QUAR_DIR / f"{qid}.qtn"
        with open(qfile, "wb") as f:
            f.write(xor_bytes(data))
            f.flush()
            os.fsync(f.fileno())
        os.chmod(qfile, 0o600)  # owner read/write only, never executable

        try:
            path.unlink()
        except OSError as e:
            qfile.unlink(missing_ok=True)  # don't keep a copy if the original is still there
            self.events.add("warning", "quarantine", f"Could not remove {path}: {e}")
            return None

        entry = {
            "id": qid, "ts": time.time(), "original_path": str(path), "mode": mode,
            "size": len(data), "sha256": detection["sha256"], "threat": detection["threat"],
            "engine": detection["engine"], "reasons": detection["reasons"],
        }
        with self._lock:
            self.entries[qid] = entry
            self._save()
        return entry

    def restore(self, qid: str) -> tuple[bool, str, dict | None]:
        with self._lock:
            entry = self.entries.get(qid)
        if not entry:
            return False, "Not found", None
        target = Path(entry["original_path"])
        if target.exists():  # never overwrite something that has appeared since
            target = target.with_name(target.name + ".restored")
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(xor_bytes((QUAR_DIR / f"{qid}.qtn").read_bytes()))
            os.chmod(target, entry["mode"] & 0o777)
        except OSError as e:
            return False, f"Restore failed: {e}", None
        self._remove(qid)
        return True, f"Restored to {target}", entry

    def delete(self, qid: str) -> bool:
        with self._lock:
            if qid not in self.entries:
                return False
        self._remove(qid)
        return True

    def _remove(self, qid: str):
        (QUAR_DIR / f"{qid}.qtn").unlink(missing_ok=True)
        with self._lock:
            self.entries.pop(qid, None)
            self._save()


# --------------------------------------------------------------------------- #
# Real-time protection and scheduler
# --------------------------------------------------------------------------- #

class RealtimeWatcher(threading.Thread):
    """
    Polls the watched folders and scans files that are new or modified.

    Polling (instead of inotify / FSEvents / ReadDirectoryChangesW) behaves the same on
    every OS using only the standard library. The trade-offs are a delay of up to
    `realtime_interval_sec` and some CPU on huge folders, so keep the watch list focused.

    A file is scanned only once its (mtime, size) is unchanged across two polls, so
    half-finished downloads aren't scanned prematurely.
    """

    def __init__(self, engine: "Engine"):
        super().__init__(daemon=True, name="realtime")
        self.engine = engine
        self.stop_event = threading.Event()
        self.known: dict[str, tuple] = {}     # path -> (mtime_ns, size) already scanned
        self.pending: dict[str, tuple] = {}   # path -> signature seen once, waiting to settle
        self.watch_key = None                 # detects changes to the watch list

    def _snapshot(self, cfg: dict) -> dict:
        prepared = Scanner.prepare(cfg)
        current = {}
        for path in self.engine.scanner.iter_files(cfg["realtime_paths"], prepared, self.stop_event):
            try:
                st = os.stat(path)
            except OSError:
                continue
            current[path] = (st.st_mtime_ns, st.st_size)
        return current

    def run(self):
        while not self.stop_event.is_set():
            cfg = self.engine.config.snapshot()
            if not cfg["realtime_enabled"]:
                self.known.clear(); self.pending.clear(); self.watch_key = None
                self.stop_event.wait(1)
                continue

            key = (tuple(cfg["realtime_paths"]), tuple(cfg["exclude_paths"]))
            if key != self.watch_key:
                # (Re)start: record what's already there as the baseline. Existing files
                # are the job of quick/full scans; real-time watches for *changes*.
                self.known = self._snapshot(cfg)
                self.pending.clear()
                self.watch_key = key
                self.engine.events.add("info", "realtime",
                                       f"Real-time protection watching {len(cfg['realtime_paths'])} folder(s), "
                                       f"{len(self.known)} files baselined")
            else:
                current = self._snapshot(cfg)
                for path, sig in current.items():
                    if self.known.get(path) == sig:
                        continue                          # unchanged since last scan
                    if self.pending.get(path) == sig:     # stable for two polls: scan it now
                        self.pending.pop(path)
                        self.known[path] = sig
                        self.engine.scan_single(path, source="real-time")
                    else:
                        self.pending[path] = sig
                # Forget files that no longer exist (deleted or quarantined).
                self.known = {p: s for p, s in self.known.items() if p in current}
                self.pending = {p: s for p, s in self.pending.items() if p in current}

            self.stop_event.wait(cfg["realtime_interval_sec"])


class Scheduler(threading.Thread):
    """Checks every 20 s whether a scheduled scan is due."""

    def __init__(self, engine: "Engine"):
        super().__init__(daemon=True, name="scheduler")
        self.engine = engine
        self.stop_event = threading.Event()

    def run(self):
        while not self.stop_event.wait(20):
            cfg = self.engine.config.snapshot()
            due = self.engine.next_scheduled_run()
            if cfg["scheduled_scan_enabled"] and due and time.time() >= due:
                ok, _ = self.engine.start_scan(cfg["scheduled_scan_type"], source="scheduled")
                if ok:
                    self.engine.mark_scheduled_run()


# --------------------------------------------------------------------------- #
# Engine: ties everything together for the web API
# --------------------------------------------------------------------------- #

class Engine:
    def __init__(self):
        for d in (DATA_DIR, QUAR_DIR, SIG_DIR):
            d.mkdir(parents=True, exist_ok=True)
        os.chmod(DATA_DIR, 0o700)  # logs and quarantine are private to your user

        self.config = Config(DATA_DIR / "config.json")
        self.events = EventLog(DATA_DIR / "events.jsonl")
        self.signatures = Signatures()
        self.scanner = Scanner(self.signatures)
        self.quarantine = Quarantine(self.events)

        self._lock = threading.RLock()
        self._state_path = DATA_DIR / "state.json"
        self.state = {"files_scanned_total": 0, "threats_total": 0, "last_scan": None,
                      "last_scheduled": 0, "detections": []}
        try:
            self.state.update(json.loads(self._state_path.read_text()))
        except (OSError, ValueError):
            pass

        self.scan = {"running": False}
        self._cancel = threading.Event()
        self.computer_roots = computer_roots()  # fixed drives rarely change; detect once
        self.watcher = RealtimeWatcher(self)
        self.scheduler = Scheduler(self)

    # -- lifecycle ---------------------------------------------------------- #

    def start(self):
        self.events.add("info", "system", "Sentinel started")
        self.watcher.start()
        self.scheduler.start()

    def stop(self):
        self._cancel.set()
        self.watcher.stop_event.set()
        self.scheduler.stop_event.set()
        self._save_state()

    def _save_state(self):
        with self._lock:
            self._state_path.write_text(json.dumps(self.state, indent=2))

    # -- detections ------------------------------------------------------------ #

    def handle_detection(self, det: dict, source: str):
        det["source"] = source
        cfg = self.config.snapshot()
        # Exact hash matches are certain enough to act on anywhere; anything else found in
        # an OS/program folder is only reported, so a false positive can't break the system.
        protected = (cfg["protect_system_files"] and det["engine"] != "signature"
                     and is_system_path(det["path"]))
        if protected and cfg["action_on_detect"] == "quarantine":
            det["action"] = "reported"
            det["reasons"].append("Not quarantined: protected system location. Review it and use "
                                  "Quarantine in the Activity tab if it's really malicious")
        elif cfg["action_on_detect"] == "quarantine":
            entry = self.quarantine.isolate(Path(det["path"]), det)
            det["action"] = "quarantined" if entry else "quarantine failed"
            det["quarantine_id"] = entry["id"] if entry else None
        else:
            det["action"] = "reported"
        with self._lock:
            self.state["threats_total"] += 1
            self.state["detections"] = [det, *self.state["detections"]][:300]
            self._save_state()
        self.events.add("threat", "detection", f"{det['threat']} in {det['path']} ({det['action']})",
                        detection_id=det["id"])

    def scan_single(self, path: str, source: str):
        cfg = Scanner.prepare(self.config.snapshot())
        det = self.scanner.scan_file(Path(path), cfg)
        with self._lock:
            self.state["files_scanned_total"] += 1
        if det:
            self.handle_detection(det, source)

    # -- scans --------------------------------------------------------------- #

    def start_scan(self, kind: str, paths: list | None = None, source: str = "manual") -> tuple[bool, str]:
        cfg = self.config.snapshot()
        if kind == "quick":
            roots = cfg["quick_scan_paths"]
        elif kind == "full":
            roots = cfg["full_scan_paths"]
        elif kind == "computer":
            roots = self.computer_roots
        elif kind == "custom":
            roots = [p for p in (paths or []) if isinstance(p, str) and p.strip()]
        else:
            return False, "Unknown scan type"
        if not roots:
            return False, "No paths to scan"

        with self._lock:
            if self.scan.get("running"):
                return False, "A scan is already running"
            self._cancel.clear()
            self.scan = {"running": True, "type": kind, "source": source, "roots": roots,
                         "started": time.time(), "files": 0, "threats": 0, "current": ""}
        threading.Thread(target=self._run_scan, args=(kind, roots, cfg), daemon=True).start()
        self.events.add("info", "scan", f"{kind.title()} scan started ({source})")
        return True, "Scan started"

    def cancel_scan(self) -> bool:
        if self.scan.get("running"):
            self._cancel.set()
            return True
        return False

    def _run_scan(self, kind: str, roots: list, cfg: dict):
        prepared = Scanner.prepare(cfg)
        try:
            for path in self.scanner.iter_files(roots, prepared, self._cancel):
                if self._cancel.is_set():
                    break
                self.scan["current"] = path
                det = self.scanner.scan_file(Path(path), prepared)
                self.scan["files"] += 1
                if det:
                    self.scan["threats"] += 1
                    self.handle_detection(det, f"{kind} scan")
        finally:
            cancelled = self._cancel.is_set()
            summary = {"type": kind, "source": self.scan["source"], "started": self.scan["started"],
                       "finished": time.time(), "files": self.scan["files"],
                       "threats": self.scan["threats"], "cancelled": cancelled}
            with self._lock:
                self.scan = {"running": False}
                self.state["files_scanned_total"] += summary["files"]
                self.state["last_scan"] = summary
                self._save_state()
            verb = "cancelled" if cancelled else "finished"
            self.events.add("warning" if summary["threats"] else "info", "scan",
                            f"{kind.title()} scan {verb}: {summary['files']} files, {summary['threats']} threat(s)")

    # -- scheduling ------------------------------------------------------------ #

    def next_scheduled_run(self) -> float | None:
        cfg = self.config.snapshot()
        if not cfg["scheduled_scan_enabled"]:
            return None
        if not self.state["last_scheduled"]:
            self.mark_scheduled_run()  # first enable: count from now
        return self.state["last_scheduled"] + cfg["scheduled_interval_hours"] * 3600

    def mark_scheduled_run(self):
        with self._lock:
            self.state["last_scheduled"] = time.time()
            self._save_state()

    # -- settings & quarantine actions --------------------------------------- #

    def update_config(self, changes: dict) -> dict:
        before = self.config.snapshot()
        after = self.config.update(changes)
        changed = [k for k in after if after[k] != before[k]]
        if changed:
            self.events.add("info", "config", "Settings changed: " + ", ".join(changed))
        if before["realtime_enabled"] and not after["realtime_enabled"]:
            self.events.add("warning", "config", "Real-time protection was turned OFF")
        if not before["scheduled_scan_enabled"] and after["scheduled_scan_enabled"]:
            self.mark_scheduled_run()
        return after

    def restore(self, qid: str, allowlist: bool = True) -> tuple[bool, str]:
        ok, msg, entry = self.quarantine.restore(qid)
        if ok and allowlist:
            # Without this, real-time protection would immediately re-quarantine the file.
            hashes = self.config.snapshot()["allowlist_hashes"]
            if entry["sha256"] not in hashes:
                self.config.update({"allowlist_hashes": [*hashes, entry["sha256"]]})
            msg += " (hash added to allowlist)"
        self.events.add("info" if ok else "warning", "quarantine", msg)
        return ok, msg

    def quarantine_detection(self, det_id: str) -> tuple[bool, str]:
        """Manually quarantine a file that was only reported (report-only mode or a protected location)."""
        with self._lock:
            det = next((d for d in self.state["detections"] if d["id"] == det_id), None)
        if not det or det.get("action") != "reported":
            return False, "Nothing to quarantine"
        path = Path(det["path"])
        try:
            current = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as e:
            return False, f"Can't read the file: {e}"
        # Never move a file that isn't the one we judged (it may have been replaced or updated).
        if current != det["sha256"]:
            return False, "The file has changed since it was detected. Scan it again first"
        entry = self.quarantine.isolate(path, det)
        if not entry:
            return False, "Quarantine failed, see the event log"
        with self._lock:
            det["action"], det["quarantine_id"] = "quarantined", entry["id"]
            self._save_state()
        self.events.add("info", "quarantine", f"Manually quarantined {path}")
        return True, f"Quarantined {path.name}"

    def delete_quarantined(self, qid: str) -> bool:
        ok = self.quarantine.delete(qid)
        if ok:
            self.events.add("info", "quarantine", f"Permanently deleted quarantined item {qid}")
        return ok

    def reload_signatures(self) -> dict:
        self.signatures.load()
        info = {"hashes": len(self.signatures.hashes), "patterns": len(self.signatures.patterns)}
        self.events.add("info", "signatures", f"Signatures reloaded: {info['hashes']} hashes, {info['patterns']} patterns")
        return info

    def clear_history(self):
        with self._lock:
            self.state["detections"] = []
            self._save_state()

    # -- status ------------------------------------------------------------------ #

    def status(self) -> dict:
        cfg = self.config.snapshot()
        clam = clamav_binary()
        return {
            "version": VERSION,
            "protection": {
                "realtime": cfg["realtime_enabled"],
                "heuristics": cfg["heuristics_enabled"],
                "archives": cfg["scan_archives"],
                "scheduled": cfg["scheduled_scan_enabled"],
                "clamav": bool(cfg["use_clamav"] and clam),
            },
            "clamav_installed": bool(clam),
            "scan": dict(self.scan),
            "stats": {
                "files_scanned_total": self.state["files_scanned_total"],
                "threats_total": self.state["threats_total"],
                "quarantined": len(self.quarantine),
                "last_scan": self.state["last_scan"],
            },
            "signatures": {"hashes": len(self.signatures.hashes),
                           "patterns": len(self.signatures.patterns),
                           "loaded_at": self.signatures.loaded_at},
            "next_scheduled": self.next_scheduled_run(),
            "realtime_paths": cfg["realtime_paths"],
            "computer_roots": self.computer_roots,
        }

    def detections(self) -> list:
        with self._lock:
            return list(self.state["detections"])
