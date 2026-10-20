"""
Packet capture: a small Wireshark-style view of this computer's own traffic.

Uses Scapy on top of a capture driver: Npcap on Windows (https://npcap.com, the driver
Wireshark installs), raw sockets on Linux (needs root). Both are optional: without them
Sentinel runs and this tab explains what to install.

What it does with each packet:
  * decodes a one-line summary like Wireshark's Info column: DNS questions and answers,
    the website name (SNI) in HTTPS handshakes, HTTP request lines, TCP flags, ARP, ICMP;
  * matches it to the program that owns the connection, using the network monitor's table;
  * learns IP -> name from DNS answers, so the Network tab can show real host names;
  * alerts when a program looks up, or opens HTTPS to, a domain on your blocked list.

Privacy: packets are kept in memory only (the newest 5000) and dropped on Clear or
when Sentinel stops, unless you save a .pcap file. Promiscuous mode is off, so only
traffic to and from this computer is captured, not other devices on your network.
Captures can contain passwords sent over unencrypted (http://) connections.
"""

from __future__ import annotations

import io
import os
import struct
import threading
import time
from collections import Counter, deque

try:
    from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, AsyncSniffer, Ether, IPv6, conf, wrpcap
    from scapy.all import get_working_ifaces
    from scapy.layers.inet6 import _ICMPv6
    try:
        from scapy.all import DNSQR, DNSRR  # noqa: F401  (register DNS record classes)
    except ImportError:
        pass
    SCAPY_ERROR = ""
except Exception as e:  # ImportError, or a broken install on some platforms
    SCAPY_ERROR = str(e)
    AsyncSniffer = None

IS_WINDOWS = os.name == "nt"
MAX_PACKETS = 5000
MAX_STORED_BYTES = 2048          # raw bytes kept per packet (for details, hex and .pcap)

ICMP_TYPES = {0: "Echo (ping) reply", 3: "Destination unreachable", 5: "Redirect",
              8: "Echo (ping) request", 11: "Time exceeded"}
TCP_FLAG_NAMES = [("F", "FIN"), ("S", "SYN"), ("R", "RST"), ("P", "PSH"), ("A", "ACK"), ("U", "URG")]
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
             33: "SRV", 65: "HTTPS"}
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ")


def tls_sni(payload: bytes) -> str | None:
    """Website name from a TLS ClientHello (sent unencrypted at the start of HTTPS).
    Every length is bounds-checked: this parses untrusted bytes off the network."""
    try:
        if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:   # handshake / ClientHello
            return None
        pos = 9 + 2 + 32                                    # record+handshake headers, version, random
        pos += 1 + payload[pos]                             # session id
        (n,) = struct.unpack_from("!H", payload, pos); pos += 2 + n          # cipher suites
        pos += 1 + payload[pos]                             # compression methods
        (ext_total,) = struct.unpack_from("!H", payload, pos); pos += 2
        end = min(pos + ext_total, len(payload))
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack_from("!HH", payload, pos); pos += 4
            if ext_type == 0 and pos + 5 <= end:            # server_name extension
                name_len = struct.unpack_from("!H", payload, pos + 3)[0]
                name = payload[pos + 5: pos + 5 + name_len]
                return name.decode("ascii", "replace") if name else None
            pos += ext_len
    except (IndexError, struct.error):
        pass
    return None


def _dns_records(section, count: int) -> list:
    """DNS sections are lists in newer Scapy and linked records in older versions."""
    if section is None or not count:
        return []
    if isinstance(section, list):
        return section
    out = []
    for i in range(count):
        try:
            out.append(section[i])
        except IndexError:
            break
    return out


def _name(v) -> str:
    if isinstance(v, bytes):
        v = v.decode("ascii", "replace")
    return str(v).rstrip(".")


class _KeepOpen(io.BytesIO):
    """wrpcap() closes the file it writes to; keep the buffer readable afterwards."""
    def close(self):
        pass


class PacketCapture:
    def __init__(self, engine):
        self.engine = engine
        self._lock = threading.Lock()
        self.packets: deque = deque(maxlen=MAX_PACKETS)
        self.next_id = 1
        self.sniffer = None
        self.running = False
        self.error = ""
        self.started_at = 0.0
        self.stopped_at = 0.0
        self.iface = ""
        self.bpf = ""
        self.total = 0
        self.total_bytes = 0
        self.protocols: Counter = Counter()
        self._owners: dict = {}            # (ip, port) -> (pid, process name)
        self._owners_at = 0.0
        self._alerted: dict = {}           # (process, domain) -> last alert time
        self._loopback = False
        self._last_raw, self._last_ts = b"", 0.0

    # -- availability ------------------------------------------------------------ #

    def available(self) -> tuple[bool, str]:
        if AsyncSniffer is None:
            return False, "scapy isn't installed. Run: py -m pip install scapy"
        try:
            ifaces = list(get_working_ifaces())
        except Exception as e:
            return False, f"Couldn't list network interfaces: {e}"
        if not ifaces:
            if IS_WINDOWS:
                return False, "Npcap isn't installed. Install it from https://npcap.com (keep 'WinPcap API-compatible mode' ticked), then restart Sentinel."
            return False, "No capturable network interfaces. Run Sentinel as root to capture packets."
        return True, ""

    def interfaces(self) -> list[dict]:
        if AsyncSniffer is None:
            return []
        out = []
        try:
            default = str(conf.iface.name if hasattr(conf.iface, "name") else conf.iface)
            for i in get_working_ifaces():
                out.append({"name": i.name, "description": getattr(i, "description", "") or i.name,
                            "ip": getattr(i, "ip", "") or "", "default": i.name == default})
        except Exception:
            pass
        return out

    # -- control ------------------------------------------------------------------- #

    def start(self, iface: str = "", bpf: str = "") -> tuple[bool, str]:
        ok, why = self.available()
        if not ok:
            return False, why
        with self._lock:
            if self.running:
                return False, "Capture is already running"
            names = {i["name"] for i in self.interfaces()}
            if iface and iface not in names:
                return False, "Unknown network interface"
            kwargs = {"prn": self._on_packet, "store": False, "promisc": False}
            if iface:
                kwargs["iface"] = iface
            if bpf.strip():
                kwargs["filter"] = bpf.strip()
            try:
                sniffer = AsyncSniffer(**kwargs)
                sniffer.start()
            except Exception as e:
                return False, self._explain(e, bool(bpf.strip()))
        # Errors (no permission, bad filter) surface on the sniffer thread just after start.
        time.sleep(0.6)
        exc = getattr(sniffer, "exception", None)
        if exc is not None or not getattr(sniffer, "running", True):
            try:
                sniffer.stop(join=False)
            except Exception:
                pass
            return False, self._explain(exc or RuntimeError("capture stopped immediately"), bool(bpf.strip()))
        with self._lock:
            self.sniffer, self.running, self.error = sniffer, True, ""
            self.started_at, self.stopped_at = time.time(), 0.0
            self.iface, self.bpf = iface or str(conf.iface), bpf.strip()
            self._loopback = not IS_WINDOWS and self.iface == "lo"
        self.engine.events.add("info", "capture", f"Packet capture started on {self.iface}"
                                                  + (f" with filter '{self.bpf}'" if self.bpf else ""))
        return True, "Capture started"

    @staticmethod
    def _explain(exc: Exception, has_filter: bool) -> str:
        msg = str(exc) or exc.__class__.__name__
        low = msg.lower()
        if "permission" in low or "operation not permitted" in low or "access" in low:
            return ("No permission to capture packets. Run Sentinel as administrator"
                    + (" (or reinstall Npcap without 'Restrict to Administrators')" if IS_WINDOWS else " (root)") + ".")
        if has_filter and ("filter" in low or "tcpdump" in low or "bpf" in low):
            hint = "" if IS_WINDOWS else " On Linux, capture filters need tcpdump installed."
            return f"The capture filter couldn't be used: {msg}.{hint} Leave it empty and use the display filter instead."
        return f"Couldn't start capture: {msg}"

    def stop(self) -> bool:
        with self._lock:
            sniffer, self.sniffer = self.sniffer, None
            was_running, self.running = self.running, False
            self.stopped_at = time.time()
        if sniffer:
            try:
                sniffer.stop(join=True)
            except Exception:
                pass
        if was_running:
            self.engine.events.add("info", "capture", f"Packet capture stopped: {self.total} packets")
        return was_running

    def clear(self):
        with self._lock:
            self.packets.clear()
            self.total = self.total_bytes = 0
            self.protocols.clear()
            self.started_at = time.time() if self.running else 0.0

    # -- per-packet work ------------------------------------------------------------- #

    def _owner_map(self) -> dict:
        """(local ip, local port) -> (pid, program), rebuilt from the network monitor every 2 s."""
        now = time.time()
        if now - self._owners_at > 2:
            owners = {}
            for c in getattr(self.engine.netmon, "connections", []):
                ip, _, port = c["local"].rpartition(":")
                if port.isdigit() and c.get("pid"):
                    owners[(ip, int(port))] = (c["pid"], c["process"])
                    owners[("*", int(port))] = (c["pid"], c["process"])   # sockets bound to 0.0.0.0 / ::
            self._owners, self._owners_at = owners, now
        return self._owners

    def _on_packet(self, pkt):
        raw = bytes(pkt)
        # On Linux the loopback interface delivers every packet twice (as sent and as received),
        # as identical bytes back to back. Wireshark shows it once, so skip the immediate twin.
        if self._loopback:
            ts = float(getattr(pkt, "time", 0))
            if raw == self._last_raw and ts - self._last_ts < 0.01:
                return
            self._last_raw, self._last_ts = raw, ts
        try:
            row, alert_domain = self._summarize(pkt)
        except Exception as e:   # never let one odd packet kill the capture thread
            row, alert_domain = {"proto": "?", "info": f"Couldn't decode: {e}", "src": "", "dst": "",
                                 "sport": None, "dport": None}, None
        with self._lock:
            # cls = the decoder for this link type (Ether, Loopback, ...), to rebuild the packet later.
            row.update(id=self.next_id, ts=float(getattr(pkt, "time", time.time())), len=len(raw),
                       raw=raw[:MAX_STORED_BYTES], cls=pkt.__class__)
            self.next_id += 1
            self.total += 1
            self.total_bytes += len(raw)
            self.protocols[row["proto"]] += 1
            self.packets.append(row)
        if alert_domain:
            self._blocked_check(row, alert_domain)

    def _summarize(self, pkt) -> tuple[dict, str | None]:
        row = {"src": "", "dst": "", "sport": None, "dport": None, "proto": pkt.lastlayer().name, "info": ""}
        domain = None

        if pkt.haslayer(ARP):
            a = pkt[ARP]
            row.update(proto="ARP", src=a.psrc, dst=a.pdst,
                       info=f"Who has {a.pdst}? Tell {a.psrc}" if a.op == 1 else f"{a.psrc} is at {a.hwsrc}")
            return row, None

        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6] if pkt.haslayer(IPv6) else None
        if ip is None:
            if pkt.haslayer(Ether):
                row.update(proto=f"Ethernet 0x{pkt[Ether].type:04x}", src=pkt[Ether].src, dst=pkt[Ether].dst)
            row["info"] = pkt.summary()
            return row, None
        row.update(src=ip.src, dst=ip.dst, proto="IPv4" if pkt.haslayer(IP) else "IPv6")

        # ICMP errors ("port unreachable"...) quote the start of the packet they're about,
        # so the quoted TCP/UDP/DNS headers must not be read as if they were this packet.
        if pkt.haslayer(ICMP) and pkt[ICMP].type in (3, 5, 11):
            icmp = pkt[ICMP]
            about = ""
            if pkt.haslayer(DNS):
                qs = _dns_records(pkt[DNS].qd, pkt[DNS].qdcount)
                about = f" (about a DNS query for {_name(qs[0].qname)})" if qs else " (about a DNS query)"
            unreachable = {0: "network", 1: "host", 3: "port"}.get(icmp.code, f"code {icmp.code}") if icmp.type == 3 else ""
            row.update(proto="ICMP", info=ICMP_TYPES.get(icmp.type, f"Type {icmp.type}")
                       + (f" ({unreachable} unreachable)" if unreachable else "") + about)
            return row, None

        if pkt.haslayer(TCP):
            t = pkt[TCP]
            payload = bytes(t.payload)
            flags = str(t.flags)
            names = ", ".join(n for f, n in TCP_FLAG_NAMES if f in flags)
            row.update(proto="TCP", sport=t.sport, dport=t.dport,
                       info=f"{t.sport} → {t.dport} [{names}] Seq={t.seq} Ack={t.ack} Win={t.window} Len={len(payload)}")
            sni = tls_sni(payload)
            if sni:
                row.update(proto="TLS", info=f"Client Hello (HTTPS handshake) → {sni}")
                domain = sni
            elif payload[:1] == b"\x16" and payload[1:2] == b"\x03":
                row.update(proto="TLS", info=f"TLS handshake  {t.sport} → {t.dport}")
            elif payload[:1] == b"\x17" and payload[1:2] == b"\x03":
                row.update(proto="TLS", info=f"Encrypted application data, {len(payload)} bytes")
            elif payload.startswith(HTTP_METHODS) or payload.startswith(b"HTTP/1."):
                first = payload.split(b"\r\n", 1)[0].decode("latin-1")[:200]
                host = next((l[5:].strip().decode("latin-1") for l in payload.split(b"\r\n")[1:20]
                             if l.lower().startswith(b"host:")), "")
                row.update(proto="HTTP", info=first + (f"  (Host: {host})" if host else ""))
                if host:
                    domain = host.split(":")[0]
        elif pkt.haslayer(UDP):
            u = pkt[UDP]
            row.update(proto="UDP", sport=u.sport, dport=u.dport, info=f"{u.sport} → {u.dport} Len={len(u.payload)}")
            if 443 in (u.sport, u.dport) and not pkt.haslayer(DNS):
                row.update(proto="QUIC", info=f"QUIC (HTTP/3)  {u.sport} → {u.dport}, {len(u.payload)} bytes")
        elif pkt.haslayer(ICMP):
            row.update(proto="ICMP", info=ICMP_TYPES.get(pkt[ICMP].type, f"Type {pkt[ICMP].type}"))
        elif pkt.haslayer(_ICMPv6):
            row.update(proto="ICMPv6", info=pkt.lastlayer().name)

        if pkt.haslayer(DNS):
            d = pkt[DNS]
            qs = _dns_records(d.qd, d.qdcount)
            qname = _name(qs[0].qname) if qs else ""
            qtype = DNS_TYPES.get(getattr(qs[0], "qtype", 0), str(getattr(qs[0], "qtype", ""))) if qs else ""
            if d.qr == 0:
                row.update(proto="DNS", info=f"Query {qtype} {qname}")
                domain = qname or None
            else:
                answers = []
                for rr in _dns_records(d.an, d.ancount):
                    rdata = rr.rdata if hasattr(rr, "rdata") else ""
                    rdata = _name(rdata) if isinstance(rdata, (bytes, str)) else str(rdata)
                    answers.append(rdata)
                    # A / AAAA answers tell us which name this IP belongs to: better than reverse DNS.
                    if getattr(rr, "type", 0) in (1, 28) and qname and not self.engine.netmon.hostnames.get(rdata):
                        self.engine.netmon.hostnames[rdata] = qname
                row.update(proto="DNS", info=f"Response {qtype} {qname} → " + (", ".join(answers[:4]) or "no answer")
                           + (f" (+{len(answers) - 4} more)" if len(answers) > 4 else ""))

        owners = self._owner_map()
        for addr, port in ((row["src"], row["sport"]), (row["dst"], row["dport"])):
            if port is not None:
                hit = owners.get((addr, port)) or owners.get(("*", port))
                if hit:
                    row["pid"], row["process"] = hit
                    break
        return row, domain

    def _blocked_check(self, row: dict, domain: str):
        """DNS lookups and HTTPS/HTTP host names give domain names directly, which is more
        precise than the network monitor's IP matching."""
        domain = domain.lower().rstrip(".")
        for b in self.engine.config.snapshot()["blocked_domains"]:
            b = b.strip().lower().lstrip("*.")
            if b and (domain == b or domain.endswith("." + b)):
                key = (row.get("process"), b)
                if time.time() - self._alerted.get(key, 0) < 600:   # same program + domain: once per 10 min
                    return
                self._alerted[key] = time.time()
                what = {"DNS": "Looked up", "TLS": "Opened an HTTPS connection to", "HTTP": "Sent an HTTP request to"}
                self.engine.add_network_alert({
                    "ts": time.time(), "level": "threat", "pid": row.get("pid"), "process": row.get("process", ""),
                    "exe": "", "target": domain, "proto": row["proto"], "kind": "capture",
                    "reasons": [f"{what.get(row['proto'], 'Contacted')} {domain}, which is on your blocked domains list (seen in packet capture)"],
                })
                return

    # -- API views -------------------------------------------------------------------- #

    def status(self) -> dict:
        ok, why = self.available()
        dur = ((self.stopped_at or time.time()) - self.started_at) if self.started_at else 0
        return {"available": ok, "reason": why, "running": self.running, "iface": self.iface, "filter": self.bpf,
                "total": self.total, "bytes": self.total_bytes, "duration": dur, "kept": len(self.packets),
                "protocols": dict(self.protocols.most_common(12)), "interfaces": self.interfaces() if ok else []}

    def list_since(self, since: int, limit: int = 1000) -> list[dict]:
        with self._lock:
            rows = [p for p in self.packets if p["id"] > since][-limit:]
        return [{k: v for k, v in p.items() if k not in ("raw", "cls")} for p in rows]

    def detail(self, pid: int) -> dict | None:
        with self._lock:
            p = next((x for x in self.packets if x["id"] == pid), None)
        if not p:
            return None
        raw = p["raw"]
        try:
            layers = p["cls"](raw).show(dump=True)
        except Exception as e:
            layers = f"(couldn't decode layers: {e})"
        hexdump = "\n".join(f"{i:04x}  {' '.join(f'{b:02x}' for b in raw[i:i+16]):<47}  "
                            + "".join(chr(b) if 32 <= b < 127 else "." for b in raw[i:i+16])
                            for i in range(0, len(raw), 16))
        return {**{k: v for k, v in p.items() if k not in ("raw", "cls")}, "layers": layers, "hex": hexdump,
                "truncated": p["len"] > len(raw)}

    def pcap_bytes(self) -> bytes | None:
        """Everything kept, as a .pcap file Wireshark can open. None if there's nothing to save."""
        if AsyncSniffer is None:
            return None
        with self._lock:
            rows = list(self.packets)
        if not rows:
            return None
        pkts = []
        for p in rows:
            try:
                pkt = p["cls"](p["raw"])
                pkt.time = p["ts"]
                pkts.append(pkt)
            except Exception:
                continue
        buf = _KeepOpen()
        wrpcap(buf, pkts)
        return buf.getvalue()
