# Sentinel: a local, private antivirus dashboard

A small antivirus-style scanner with a web dashboard. It runs entirely on your own machine:
no cloud lookups, no telemetry, no accounts. It's pure Python standard library, so there's nothing to install.

```bash
python3 sentinel.py            # then open http://127.0.0.1:8765
python3 sentinel.py --port 9000
```

> **Scope:** Sentinel is a learning project and a useful extra layer, not a replacement for a
> maintained commercial or open-source antivirus. Its built-in signatures are only test entries,
> so its real strength comes from the heuristics, the optional ClamAV engine, and any hash feeds
> you add yourself.

## Features

| Feature | What it does |
|---|---|
| **Real-time protection** | Watches chosen folders and scans new or changed files once they finish writing |
| **Quick / Full / Custom scans** | On-demand scans with live progress and cancel |
| **Scheduled scans** | Quick or full scan every N hours |
| **Hash signatures** | SHA-256 matching against `signatures/*.hashes` |
| **Pattern rules** | Text/hex byte patterns from `signatures/patterns.json` |
| **Heuristics** | Score-based: double extensions, RTL-override filenames, executables disguised as documents, packed (high-entropy) executables, obfuscated scripts, Office macros, hidden executables in temp/download folders |
| **Archive scanning** | Looks inside `.zip` files, with zip-bomb limits |
| **ClamAV integration** | Optional second engine if `clamdscan`/`clamscan` is installed |
| **Quarantine** | Moves detected files into a vault, scrambled and non-executable; restore or delete them from the UI |
| **Exclusions** | Folders, extensions and allowlisted hashes |
| **Sensitivity levels** | Low / Medium / High heuristic thresholds |
| **Report-only mode** | Flag threats without moving them |
| **Activity log** | Detection history with reasons, plus a filterable event log |

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

## Adding real signatures

- **Hashes:** drop any `*.hashes` file into `signatures/`, one SHA-256 per line, optionally followed by a name.
  Hash lists exported from threat-intel sources you trust work well. Then click **Settings → Reload signatures**.
- **Patterns:** add rules to `signatures/patterns.json`:
  ```json
  {"name": "My.Rule", "strings": ["some text"], "hex": ["deadbeef"], "match": "any"}
  ```
- **ClamAV** (recommended for real-world coverage): `sudo apt install clamav clamav-daemon && sudo freshclam`,
  then enable "Use ClamAV engine" in Settings.

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

## Limitations

- It can't block a file *before* it's opened (true on-access blocking needs a kernel driver).
  Sentinel catches files shortly after they land.
- It runs with your user's permissions, so it can't scan or quarantine files you can't access.
- Heuristics produce false positives. Use the allowlist or lower the sensitivity if something legitimate gets flagged.
