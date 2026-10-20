# Sentinel: a local, private antivirus dashboard

A small antivirus-style scanner with a web dashboard. It runs entirely on your own machine:
no cloud lookups, no telemetry, no accounts. The core is pure Python standard library. One optional package,
[psutil](https://pypi.org/project/psutil/), enables the process and network monitors:

```bash
python3 -m pip install -r requirements.txt   # optional: process + network monitors
python3 sentinel.py            # then open http://127.0.0.1:8765
python3 sentinel.py --port 9000
```

**Windows:** install Python 3.9+ from [python.org](https://www.python.org/downloads/) and tick
**"Add python.exe to PATH"** in the installer. Then run it with `py` (or `python`) instead of `python3`:

```
py -m pip install -r requirements.txt
py sentinel.py
py tools\make_test_files.py %USERPROFILE%\Downloads\sentinel-test
```

On Windows, `python3` usually opens a Microsoft Store shortcut, which gives the error
*"Python was not found; run without arguments to install from the Microsoft Store"*.

> **Scope:** Sentinel is a learning project and a useful extra layer, not a replacement for a
> maintained commercial or open-source antivirus. Its built-in signatures are only test entries,
> so its real strength comes from the heuristics, the optional ClamAV engine, and any hash feeds
> you add yourself.

## Features

| Feature | What it does |
|---|---|
| **Real-time protection** | Watches chosen folders and scans new or changed files once they finish writing |
| **Quick / Full / Computer / Custom scans** | On-demand scans with live progress and cancel. Computer scan covers every local fixed drive (`C:\`, `D:\`…) or `/` |
| **Scheduled scans** | Quick or full scan every N hours |
| **Hash signatures** | SHA-256 matching against `signatures/*.hashes` |
| **Pattern rules** | Text/hex byte patterns from `signatures/patterns.json` |
| **Heuristics** | Score-based: double extensions, RTL-override filenames, executables disguised as documents, packed (high-entropy) executables, obfuscated scripts, Office macros, hidden executables in temp/download folders |
| **Archive scanning** | Looks inside `.zip` files, with zip-bomb limits |
| **ClamAV integration** | Optional second engine if `clamdscan`/`clamscan` is installed |
| **Quarantine** | Moves detected files into a vault, scrambled and non-executable; restore or delete them from the UI |
| **Exclusions** | Folders, extensions and allowlisted hashes |
| **Sensitivity levels** | Low / Medium / High heuristic thresholds |
| **Report-only mode** | Flag threats without moving them, then quarantine individual files from the Activity tab |
| **System file protection** | In Windows / Program Files (or `/usr`, `/etc`… on Linux), only exact hash matches are auto-quarantined; other detections are reported for review |
| **Activity log** | Detection history with reasons, plus a filterable event log |
| **Process monitor** | Behaviour-based checks on programs as they start (Office apps launching shells, fake system processes, encoded or download-and-run PowerShell, misused built-in tools, programs running from Temp/Downloads), plus scan-on-launch. Suspend, resume or stop processes from the dashboard. Needs psutil |
| **Network monitor** | Live upload/download graph, every connection with its program and remote host name, listening ports, a log of new connections (CSV export), and alerts for blocked domains, remote-access ports and network use from temp folders. Needs psutil |
| **URL / phishing checker** | Offline check of a pasted link: lookalike domains (`paypa1`, `rnicrosoft`), disguised characters, `@` tricks, raw or obfuscated IPs, shorteners, risky TLDs |
| **Blocked domains** | Your own list: flagged by the URL checker, and the network monitor alerts if any program connects to them |

## Try it with harmless test files

```bash
python3 tools/make_test_files.py ~/Downloads/sentinel-test
```

This creates files that *look* suspicious to each engine (one for hashes, patterns, the double-extension
heuristic, the disguised-executable heuristic, and archives) plus one clean control file. None of them can run or do anything.
Start a **Custom scan** on that folder. If real-time protection watches `~/Downloads`, they're picked up automatically within a few seconds.

## How it works

```
sentinel.py        Web server (localhost only) + JSON API
engine.py          Config, signatures, heuristics, scanner, quarantine, real-time watcher, scheduler
procmon.py         Process monitor: behaviour rules, scan on launch, suspend/resume/stop
netmon.py          Network monitor: connections, traffic rates, connection log, alerts
urlcheck.py        Offline URL / phishing checker
static/index.html  Dashboard (plain HTML/CSS/JS, no build step)
signatures/        Your detection rules: *.hashes and patterns.json
tools/             Helper scripts
data/              Created at runtime: config, logs, state, quarantine (git-ignored)
```

Each file goes through the engines in order and the first match wins:
exclusions → hash → pattern → heuristics → archive members → ClamAV.

**Heuristic scoring.** Each suspicious trait adds points, and a file is flagged when its total reaches the threshold
(Low 75, Medium 50, High 35). Click "Details" on any detection to see which traits contributed.

**Real-time protection** polls the watched folders every few seconds. Polling works the same on every OS,
but keep the watch list focused (Downloads, Desktop) rather than your whole disk.
Files that existed before protection was turned on become the baseline; run a quick scan to check them.

**Quarantine** XORs the file contents before storing them with owner-only permissions. This isn't encryption.
It just makes sure the file can't be executed or opened by accident and won't trip other scanners.

## Scanning the whole computer

Click **Computer scan** on the dashboard. On Windows it scans every local fixed drive, skipping network, CD and RAM drives.
It reads every file (up to the size limit), so expect it to take a while: roughly 20–60+ minutes depending on
the number of files and disk speed. You can keep working and cancel at any time. Files Sentinel isn't allowed to
read (other users' files, files locked by Windows) are skipped; run it as administrator to cover more.

Because heuristics can misfire, **Protect system files** (on by default) stops Sentinel from auto-quarantining
anything in OS and program folders unless it's an exact hash-signature match. Those detections show as
*reported* in the Activity tab, with a **Quarantine** button if you decide a file really is malicious.

## Adding real signatures

- **Hashes:** drop any `*.hashes` file into `signatures/`, one SHA-256 per line, optionally followed by a name.
  Hash lists exported from threat-intel sources you trust work well. Then click **Settings → Reload signatures**.
- **Patterns:** add rules to `signatures/patterns.json`:
  ```json
  {"name": "My.Rule", "strings": ["some text"], "hex": ["deadbeef"], "match": "any"}
  ```
- **ClamAV** (recommended for real-world coverage): install it, download its virus definitions, then enable
  "Use ClamAV engine" in Settings. The badge next to it should say **working**; if not, the text under it says why.
  - **Linux:** `sudo apt install clamav clamav-daemon && sudo freshclam`
  - **Windows:** install the `.msi` from [clamav.net/downloads](https://www.clamav.net/downloads) (it goes to
    `C:\Program Files\ClamAV`, which Sentinel checks automatically). ClamAV won't scan until it has virus
    definitions, so in a command prompt **run as administrator**:
    ```
    cd "C:\Program Files\ClamAV"
    copy conf_examples\freshclam.conf.sample freshclam.conf
    notepad freshclam.conf        (delete the line that just says "Example", save)
    freshclam.exe                 (downloads the definitions, a few hundred MB)
    ```
    Then click **Re-check** next to the ClamAV setting.
  - **How Sentinel uses it:** if the clamd background service is running, every file is checked as it's scanned.
    Otherwise Sentinel runs one ClamAV pass after each scan (ClamAV takes 10-30 s to load its definitions, too slow
    to repeat per file), and real-time protection checks new files one at a time.

## Security of the dashboard

- Binds to `127.0.0.1` only, so it's unreachable from your network.
- Rejects non-localhost `Host` headers (DNS-rebinding protection).
- All POST requests need an `X-Sentinel: 1` header. Browsers can't send that cross-site without a CORS
  pre-flight, which is never approved, so websites you visit can't control Sentinel.
- File names are HTML-escaped everywhere in the UI, so a maliciously named file can't inject script.

## Run at login (Linux, systemd user service)

```ini
# ~/.config/systemd/user/sentinel.service
[Unit]
Description=Sentinel local antivirus

[Service]
ExecStart=/usr/bin/python3 /path/to/antivirus_local/sentinel.py
Restart=on-failure

[Install]
WantedBy=default.target
```

```bash
systemctl --user enable --now sentinel
```

## Process monitor, network monitor and web protection

**Process monitor.** Every couple of seconds Sentinel looks for programs that have just started and scores them on
what launched them, where they run from and what their command line does. With **Settings → Process monitor →
Suspend it**, a flagged program is frozen until you resume or stop it from the Processes tab. Core Windows processes
and Sentinel itself can never be suspended or stopped. Add programs you trust under *Trusted programs*.
Running Sentinel as administrator lets it see the details of, and control, other users' and system processes.

**Network monitor.** This works at the connection level, like Resource Monitor or TCPView: which program talks to
which address and port, and how much traffic flows in total. It does **not** capture packet contents the way
Wireshark does; that needs a packet-capture driver (Npcap) and administrator rights. Remote host names come from
reverse DNS lookups, which you can turn off in Settings so no DNS queries are sent.

**URL checker.** Links are judged from their text only. They're never opened, and nothing leaves your computer.
"No obvious warning signs" isn't proof a site is safe; keep your browser's built-in protection on too.

## Limitations

- It can't block a file *before* it's opened (true on-access blocking needs a kernel driver).
  Sentinel catches files shortly after they land.
- It runs with your user's permissions, so it can't scan or quarantine files you can't access.
- Without a kernel driver it can't stop a program *before* it starts, see inside other programs' memory,
  block exploits, or capture packets. The process monitor reacts within a couple of seconds of a program starting.
  Windows Security (Defender, Controlled Folder Access, Exploit Protection, SmartScreen) covers those layers.
- Heuristics produce false positives. Use the allowlist or lower the sensitivity if something legitimate gets flagged.
