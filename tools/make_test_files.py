#!/usr/bin/env python3
"""
Create HARMLESS test files that trigger each of Sentinel's detection engines.

    python3 tools/make_test_files.py ~/Downloads/sentinel-test

None of these files can do anything: they are plain text or random bytes that
only *look* suspicious to the rules. Point a custom scan at the folder (or create
it inside a watched folder to see real-time protection react).
"""

import io
import os
import sys
import zipfile
from pathlib import Path


def main():
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "sentinel-test").expanduser()
    target.mkdir(parents=True, exist_ok=True)

    files = {
        # Hash engine: SHA-256 is listed in signatures/local.hashes.
        "hash-test.txt": b"Sentinel harmless hash-signature test file\n",
        # Pattern engine: contains the marker from signatures/patterns.json.
        "pattern-test.txt": b"This file contains SENTINEL-HARMLESS-PATTERN-TEST and nothing else.\n",
        # Heuristic: double extension (looks like a PDF, named as an .exe). Content is plain text.
        "invoice.pdf.exe": b"Harmless text file used to test the double-extension heuristic.\n",
        # Heuristic: "MZ" header (fake executable) + random bytes, named .jpg.
        # Triggers "disguised executable" + "high entropy". It isn't a valid program.
        "holiday-photo.jpg": b"MZ" + os.urandom(64 * 1024),
        # Clean control file: should NOT be flagged.
        "clean-notes.txt": b"Just some ordinary notes.\n",
    }
    for name, data in files.items():
        (target / name).write_bytes(data)

    # Archive engine: the pattern-test file inside a zip.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("docs/readme.txt", files["pattern-test.txt"])
    (target / "archive-test.zip").write_bytes(buf.getvalue())

    print(f"Created {len(files) + 1} test files in {target}")
    print("Expected: 5 detections (hash, pattern, 2 heuristic, archive); clean-notes.txt stays clean.")


if __name__ == "__main__":
    main()
