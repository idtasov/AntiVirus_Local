"""
Network monitor: which programs talk to which addresses, plus live traffic rates.

This works at the *connection* level, like Resource Monitor or TCPView, not the packet
level like Wireshark. Capturing packets needs a capture driver (Npcap on Windows) and
admin rights; reading the OS connection table needs neither and already answers the key
security question: "what is this program connecting to?"

Each poll:
  * reads total bytes sent/received to draw the traffic graph,
  * lists TCP/UDP sockets with their owning process,
  * logs connections and listening ports that weren't there before,
  * raises alerts for connections to blocked domains, to ports typical of remote-access
    tools, from programs running out of temp/download folders, or from processes the
    process monitor flagged.

Requires psutil. Remote host names come from reverse DNS in a background thread, so a
slow lookup never stalls monitoring (turn it off in Settings to send no DNS queries).
"""

from __future__ import annotations

import os
import queue
import socket
import threading
import time
from collections import deque

try:
    import psutil
except ImportError:
    psutil = None

from procmon import WRITABLE_DIRS


class NetworkMonitor(threading.Thread):
    def __init__(self, engine):
        super().__init__(daemon=True, name="netmon")
        self.engine = engine
        self.stop_event = threading.Event()
        self.history: deque = deque(maxlen=150)      # (ts, sent_bytes_per_s, recv_bytes_per_s)
        self.log: deque = deque(maxlen=2000)         # newly seen connections/listeners
        self.connections: list[dict] = []            # latest snapshot
        self.known: set = set()
        self.error = ""
        self._last_io = None
        self._proc_cache: dict[int, tuple] = {}      # pid -> (create_time, name, exe)
        # Reverse DNS and blocked-domain resolution run on their own thread.
        self.hostnames: dict[str, str | None] = {}
        self._dns_queue: queue.Queue = queue.Queue(maxsize=1000)
        self.blocked_ips: dict[str, str] = {}        # ip -> blocked domain it belongs to
        self._blocked_key: tuple = ()
        self._blocked_at = 0.0
        self._recent_alerts: dict[tuple, float] = {}  # (pid, address, reasons) -> last raised

    @staticmethod
    def available() -> bool:
        return psutil is not None

    # -- threads ----------------------------------------------------------------- #

    def run(self):
        if not self.available():
            return
        threading.Thread(target=self._dns_worker, daemon=True, name="netmon-dns").start()
        first = True
        while not self.stop_event.is_set():
            cfg = self.engine.config.snapshot()
            if cfg["network_monitor_enabled"]:
                self._refresh_blocklist(cfg)
                self._poll(cfg, baseline=first)
                first = False
            else:
                first, self._last_io = True, None
                self.known.clear()
            self.stop_event.wait(cfg["network_interval_sec"])

    def _dns_worker(self):
        while not self.stop_event.is_set():
            try:
                kind, value = self._dns_queue.get(timeout=1)
            except queue.Empty:
                continue
            if kind == "ptr":
                try:
                    self.hostnames[value] = socket.gethostbyaddr(value)[0]
                except (OSError, UnicodeError):
                    self.hostnames[value] = ""      # no name; don't ask again
                if len(self.hostnames) > 20000:
                    self.hostnames.clear()
            elif kind == "blocklist":
                ips = {}
                for domain in value:
                    try:
                        for info in socket.getaddrinfo(domain, None):
                            ips[info[4][0]] = domain
                    except (OSError, UnicodeError):
                        pass
                self.blocked_ips = ips

    def _refresh_blocklist(self, cfg: dict):
        """Blocked domains are names, but connections are IPs: resolve the list every 10
        minutes (and right away whenever it changes) so connections can be matched."""
        key = tuple(d.strip().lower().lstrip("*.") for d in cfg["blocked_domains"] if d.strip())
        if key != self._blocked_key or time.time() - self._blocked_at > 600:
            self._blocked_key, self._blocked_at = key, time.time()
            if not key:
                self.blocked_ips = {}
            else:
                try:
                    self._dns_queue.put_nowait(("blocklist", key))
                except queue.Full:
                    pass

    # -- polling ------------------------------------------------------------------ #

    def _process(self, pid: int | None) -> tuple[str, str]:
        if not pid:
            return "", ""
        try:
            proc = psutil.Process(pid)
            ctime = proc.create_time()
            cached = self._proc_cache.get(pid)
            if cached and cached[0] == ctime:
                return cached[1], cached[2]
            name = proc.name()
            try:
                exe = proc.exe()
            except (psutil.AccessDenied, OSError):
                exe = ""
            self._proc_cache[pid] = (ctime, name, exe)
            return name, exe
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return "", ""

    def _poll(self, cfg: dict, baseline: bool):
        now = time.time()
        io = psutil.net_io_counters()
        if self._last_io:
            t0, sent0, recv0 = self._last_io
            dt = max(now - t0, 1e-6)
            self.history.append((now, max(io.bytes_sent - sent0, 0) / dt, max(io.bytes_recv - recv0, 0) / dt))
        self._last_io = (now, io.bytes_sent, io.bytes_recv)

        try:
            raw = psutil.net_connections(kind="inet")
            self.error = ""
        except psutil.AccessDenied:
            # macOS (and some Linux setups) only show other programs' sockets to root.
            self.error = "The OS hides other programs' connections from Sentinel. Run it as administrator to see them all."
            raw = []

        alert_ports = {int(p) for p in cfg["network_alert_ports"] if str(p).strip().isdigit()}
        current, snapshot = set(), []
        for c in raw:
            if c.status == psutil.CONN_TIME_WAIT:
                continue   # already closed, just lingering in the OS table; owned by no process
            proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
            name, exe = self._process(c.pid)
            local = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            rip, rport = (c.raddr.ip, c.raddr.port) if c.raddr else ("", None)
            listening = c.status == psutil.CONN_LISTEN or (proto == "UDP" and not rip)
            row = {"pid": c.pid, "process": name, "exe": exe, "proto": proto, "local": local,
                   "remote_ip": rip, "remote_port": rport, "status": c.status if proto == "TCP" else "",
                   "listening": listening, "host": self.hostnames.get(rip, "") if rip else ""}
            snapshot.append(row)

            if listening:
                key = ("listen", c.pid, proto, local)
            elif rip:
                key = ("conn", c.pid, proto, rip, rport)
            else:
                continue
            current.add(key)
            if key in self.known:
                continue
            self.known.add(key)
            if rip and cfg["network_reverse_dns"] and rip not in self.hostnames and not _is_local(rip):
                self.hostnames[rip] = None     # mark as pending
                try:
                    self._dns_queue.put_nowait(("ptr", rip))
                except queue.Full:
                    self.hostnames.pop(rip, None)
            entry = {**row, "ts": now, "kind": "listen" if listening else "connect", "existing": baseline}
            self.log.append(entry)
            if not baseline:
                self._check(entry, alert_ports)

        self.known &= current
        self.connections = snapshot
        if len(self._proc_cache) > 5000:
            self._proc_cache.clear()

    # -- alerts ------------------------------------------------------------------ #

    def _check(self, e: dict, alert_ports: set[int]):
        who = f"{e['process'] or 'Unknown process'} (PID {e['pid']})" if e["pid"] else "Unknown process"
        target = f"{e['remote_ip']}:{e['remote_port']}" if e["remote_ip"] else e["local"]
        exe = os.path.normcase(e["exe"] or "")
        reasons, level = [], "warning"

        if e["remote_ip"] in self.blocked_ips:
            reasons.append(f"Connected to {self.blocked_ips[e['remote_ip']]}, which is on your blocked domains list")
            level = "threat"
        if e["remote_port"] in alert_ports:
            reasons.append(f"Remote port {e['remote_port']} is commonly used by remote-access tools, IRC bots or Tor")
        if exe and any(exe.startswith(d.lower()) for d in WRITABLE_DIRS):
            what = "Listens for incoming connections" if e["kind"] == "listen" else "Uses the network"
            reasons.append(f"{what} from a temporary or download folder")
        procmon = getattr(self.engine, "procmon", None)
        if procmon and any(k[0] == e["pid"] for k in procmon.verdicts):
            reasons.append("This process was flagged by the process monitor")
            level = "threat"

        if reasons:
            # The same program reconnecting to the same address (new local port each time)
            # would otherwise raise an identical alert per connection.
            key = (e["pid"], e["remote_ip"] or e["local"], tuple(reasons))
            if e["ts"] - self._recent_alerts.get(key, 0) < 600:
                return
            self._recent_alerts[key] = e["ts"]
            if len(self._recent_alerts) > 5000:
                self._recent_alerts.clear()
            self.engine.add_network_alert({"ts": e["ts"], "level": level, "pid": e["pid"], "process": e["process"],
                                           "exe": e["exe"], "target": target, "proto": e["proto"],
                                           "kind": e["kind"], "reasons": reasons})

    # -- API views ---------------------------------------------------------------- #

    def view(self) -> dict:
        conns = self.connections
        for row in conns:  # fill in names resolved since the last poll
            if row["remote_ip"] and not row["host"]:
                row["host"] = self.hostnames.get(row["remote_ip"]) or ""
        rate = self.history[-1] if self.history else (0, 0, 0)
        return {
            "available": self.available(),
            "error": self.error,
            "rate": {"sent": rate[1], "recv": rate[2]},
            "history": [[round(t, 1), round(s), round(r)] for t, s, r in self.history],
            "summary": {
                "connections": sum(1 for c in conns if c["remote_ip"]),
                "listening": sum(1 for c in conns if c["listening"]),
                "processes": len({c["pid"] for c in conns if c["pid"]}),
                "remote_hosts": len({c["remote_ip"] for c in conns if c["remote_ip"]}),
            },
            "connections": conns,
            "blocked_ips": len(self.blocked_ips),
        }

    def log_entries(self, limit: int = 2000) -> list[dict]:
        out = []
        for e in list(self.log)[-limit:][::-1]:
            if e["remote_ip"] and not e["host"]:
                e = {**e, "host": self.hostnames.get(e["remote_ip"]) or ""}
            out.append(e)
        return out


def _is_local(ip: str) -> bool:
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
        return a.is_loopback or a.is_link_local or a.is_unspecified
    except ValueError:
        return True
