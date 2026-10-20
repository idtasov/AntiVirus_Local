#!/usr/bin/env python3
"""
Sentinel: a small, private, local antivirus-style monitor with a web dashboard.

    python3 sentinel.py              # then open http://127.0.0.1:8765
    python3 sentinel.py --port 9000

Only the Python standard library is used, so there's nothing to install.

Security of the local web UI:
  * It binds to 127.0.0.1 only, so other machines on your network can't reach it.
  * Requests whose Host header isn't localhost are rejected (blocks DNS-rebinding,
    where a malicious site points its own domain at 127.0.0.1).
  * State-changing requests (POST) must carry the custom header "X-Sentinel: 1".
    A browser won't let another website send a custom header here without a CORS
    pre-flight, which this server never approves, so web pages you visit can't start
    scans or restore quarantined files behind your back.
"""

from __future__ import annotations

import argparse
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from engine import BASE_DIR, Engine

STATIC = BASE_DIR / "static"


def make_handler(engine: Engine, port: int):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "Sentinel/1.0"

        def log_message(self, fmt, *args):
            pass  # keep the terminal quiet; meaningful events go to the Activity tab

        # -- helpers ------------------------------------------------------------- #

        def _send(self, code: int, body, ctype: str = "application/json"):
            if not isinstance(body, bytes):
                body = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")  # no embedding in other sites
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                             "script-src 'self' 'unsafe-inline'; img-src 'self' data:")
            self.end_headers()
            self.wfile.write(body)

        def _host_ok(self) -> bool:
            return self.headers.get("Host", "") in allowed_hosts

        def _json_body(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            if length > 1_000_000:
                raise ValueError("Request body too large")
            data = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(data, dict):
                raise ValueError("Expected a JSON object")
            return data

        # -- routes -------------------------------------------------------------- #

        def do_GET(self):
            if not self._host_ok():
                return self._send(403, {"error": "Forbidden host"})
            path = self.path.split("?", 1)[0]

            if path in ("/", "/index.html"):
                return self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
            if path == "/api/status":
                return self._send(200, engine.status())
            if path == "/api/config":
                return self._send(200, engine.config.snapshot())
            if path == "/api/events":
                return self._send(200, engine.events.list(300))
            if path == "/api/quarantine":
                return self._send(200, engine.quarantine.list())
            if path == "/api/detections":
                return self._send(200, engine.detections())
            return self._send(404, {"error": "Not found"})

        def do_POST(self):
            if not self._host_ok() or self.headers.get("X-Sentinel") != "1":
                return self._send(403, {"error": "Forbidden"})
            try:
                body = self._json_body()
            except ValueError as e:
                return self._send(400, {"error": str(e)})
            path = self.path.split("?", 1)[0]

            if path == "/api/config":
                return self._send(200, engine.update_config(body))
            if path == "/api/scan":
                ok, msg = engine.start_scan(body.get("type", ""), body.get("paths"))
                return self._send(200 if ok else 409, {"ok": ok, "message": msg})
            if path == "/api/scan/cancel":
                return self._send(200, {"ok": engine.cancel_scan()})
            if path == "/api/signatures/reload":
                return self._send(200, engine.reload_signatures())
            if path == "/api/detections/clear":
                engine.clear_history()
                return self._send(200, {"ok": True})

            m = re.fullmatch(r"/api/quarantine/([0-9a-f]{12})/(restore|delete)", path)
            if m:
                qid, action = m.groups()
                if action == "restore":
                    ok, msg = engine.restore(qid, allowlist=bool(body.get("allowlist", True)))
                else:
                    ok = engine.delete_quarantined(qid)
                    msg = "Deleted" if ok else "Not found"
                return self._send(200 if ok else 404, {"ok": ok, "message": msg})

            return self._send(404, {"error": "Not found"})

    return Handler


def main():
    parser = argparse.ArgumentParser(description="Sentinel local antivirus dashboard")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    engine = Engine()
    engine.start()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(engine, args.port))
    print(f"Sentinel running: http://127.0.0.1:{args.port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        engine.stop()
        server.server_close()
        print("Sentinel stopped.")


if __name__ == "__main__":
    main()
