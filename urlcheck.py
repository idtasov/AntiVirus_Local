"""
URL / phishing checker: judges a link from its text alone.

Fully offline: the link is never opened and nothing is sent anywhere. That keeps it
private and safe (visiting a phishing page can itself be risky), but it also means a
clean result is "no obvious warning signs", not a guarantee. Phishing sites on fresh,
plain-looking domains won't show these signs; your browser's built-in protection
(SmartScreen / Safe Browsing) checks against live lists of known-bad sites.

Each check adds points, like the file heuristics:
    >= 60  dangerous     >= 30  suspicious     below  no obvious signs
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit

# Brands phishers imitate most, with the domains they really use. A brand name showing up
# on any other domain ("paypal.secure-login.example") is a strong phishing sign.
BRANDS = {
    "paypal": ("paypal.com", "paypal.me"),
    "apple": ("apple.com", "icloud.com"),
    "icloud": ("icloud.com", "apple.com"),
    "microsoft": ("microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com", "bing.com", "msn.com"),
    "office365": ("office.com", "microsoft.com", "microsoftonline.com"),
    "outlook": ("outlook.com", "live.com", "office.com", "microsoft.com"),
    "google": ("google.com", "gmail.com", "youtube.com", "goo.gl"),
    "gmail": ("gmail.com", "google.com"),
    "amazon": ("amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it", "amazon.es", "amazon.ca", "amzn.to"),
    "netflix": ("netflix.com"),
    "facebook": ("facebook.com", "fb.com", "fb.me"),
    "instagram": ("instagram.com"),
    "whatsapp": ("whatsapp.com", "whatsapp.net"),
    "linkedin": ("linkedin.com"),
    "dropbox": ("dropbox.com"),
    "docusign": ("docusign.com", "docusign.net"),
    "steam": ("steampowered.com", "steamcommunity.com"),
    "coinbase": ("coinbase.com"),
    "binance": ("binance.com"),
    "dhl": ("dhl.com", "dhl.de"),
    "fedex": ("fedex.com"),
    "usps": ("usps.com"),
    "github": ("github.com", "github.io"),
}

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
              "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id"}

# TLDs that are cheap or confusing ("invoice.zip" looks like a file) and over-represented
# in phishing reports. Plenty of legitimate sites use them too, so the weight is small.
RISKY_TLDS = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "kim",
              "work", "rest", "fit", "loan", "men", "gdn", "support", "cam", "icu", "quest"}

LURE_WORDS = ("login", "log-in", "signin", "sign-in", "verify", "verification", "account", "secure",
              "update", "unlock", "suspended", "confirm", "password", "billing", "wallet", "recover")

# Characters people (and fonts) confuse. Used to unmask lookalikes like "paypa1" or "rnicrosoft".
CONFUSABLES = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("@", "a")]

# Home/office network ranges: router and NAS admin pages legitimately use raw IPs here.
LAN_NETS = [ipaddress.ip_network(n) for n in
            ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
             "::1/128", "fc00::/7", "fe80::/10")]

# Second-level labels used under country TLDs (example.co.uk, example.com.au).
GENERIC_SLDS = {"co", "com", "org", "net", "gov", "ac", "edu", "or", "ne", "go"}


def registered_domain(host: str) -> str:
    """Best-effort 'example.co.uk' from 'login.example.co.uk' (no public-suffix list needed)."""
    labels = host.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in GENERIC_SLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _unconfuse(text: str) -> str:
    for fake, real in CONFUSABLES:
        text = text.replace(fake, real)
    return text


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein distance: how many single-character edits turn a into b."""
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _decode_idna(host: str) -> str:
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return host


def _parse_ip(host: str):
    """Recognise normal IPs and the obfuscated forms browsers also accept
    (http://3232235777/ or http://0xC0A80101/ are both 192.168.1.1)."""
    try:
        return ipaddress.ip_address(host.strip("[]")), False
    except ValueError:
        pass
    try:
        if re.fullmatch(r"\d{8,10}", host):
            return ipaddress.ip_address(int(host)), True
        if re.fullmatch(r"0x[0-9a-f]{1,8}", host):
            return ipaddress.ip_address(int(host, 16)), True
    except ValueError:
        pass
    return None, False


def check_url(url: str, blocked_domains: list[str] | None = None) -> dict:
    score, reasons = 0, []

    def flag(points: int, reason: str):
        nonlocal score
        score += points
        reasons.append({"points": points, "reason": reason})

    raw = (url or "").strip()
    if not raw:
        return {"error": "Enter a link to check"}
    if not re.match(r"^[a-z][a-z0-9+.-]*:", raw, re.I):
        raw = "http://" + raw          # people often paste "example.com/login"
    try:
        parts = urlsplit(raw)
        host = (parts.hostname or "").rstrip(".").lower()
    except ValueError:
        return {"error": "That doesn't look like a valid link"}

    scheme = parts.scheme.lower()
    if scheme in ("javascript", "data", "vbscript"):
        flag(80, f"'{scheme}:' link runs code or embeds content instead of opening a website")
        return _verdict(raw, host, "", score, reasons)
    if not host:
        return {"error": "Couldn't find a website name in that link"}

    reg = host if _parse_ip(host)[0] is not None else registered_domain(host)
    reg_label = reg.split(".")[0]
    unicode_host = _decode_idna(host)

    # 1. Blocklist you maintain.
    for d in blocked_domains or []:
        d = d.strip().lower().lstrip("*.")
        if d and (host == d or host.endswith("." + d)):
            flag(100, f"On your blocked domains list ({d})")
            break

    # 2. Hiding the real destination.
    if "@" in (parts.netloc or ""):
        flag(45, "Contains '@' before the host: everything before it is ignored, so the link "
                 f"really goes to {host}")
    ip, obfuscated = _parse_ip(host)
    if ip is not None:
        if obfuscated:
            flag(50, f"Address written in an unusual numeric form to hide that it's {ip}")
        elif not any(ip in net for net in LAN_NETS if net.version == ip.version):
            flag(30, "Uses a raw IP address instead of a website name")
    if reg in SHORTENERS or host in SHORTENERS:
        flag(15, "Link shortener: the real destination is hidden until you click")

    # 3. Lookalike characters and names.
    if host.startswith("xn--") or ".xn--" in host:
        flag(30, f"Internationalised domain (shown as '{unicode_host}'): may use foreign letters that look like Latin ones")
    elif any(ord(c) > 127 for c in unicode_host):
        flag(30, "Contains non-Latin characters that can imitate normal letters")
    if ip is None:
        legit = any(reg in domains for domains in BRANDS.values())
        if not legit:
            name = unicodedata.normalize("NFKD", _decode_idna(reg_label))
            name = "".join(c for c in name if c.isascii()).lower()
            plain = _unconfuse(name)
            # Check the whole name and each hyphenated part: "rnicrosoft-support" -> "microsoft".
            tokens = {plain, *plain.split("-")}
            for brand, domains in BRANDS.items():
                if len(brand) < 4:
                    continue
                if any(t == brand or (len(brand) >= 6 and _edit_distance(t, brand) == 1) for t in tokens):
                    flag(60, f"'{reg}' imitates {brand} (real site: {domains[0]})")
                    break
            else:
                # A brand in the host name is a classic trick; in the path it's often innocent
                # (news articles, wikis), so it only adds a little on top of other signs.
                in_host, in_path = _unconfuse(host), _unconfuse((parts.path or "").lower())
                for brand, domains in BRANDS.items():
                    if brand in in_host:
                        flag(40, f"Host name contains '{brand}' but the site is {reg}, not {domains[0]}")
                        break
                    if brand in in_path:
                        flag(15, f"Mentions '{brand}' but the site is {reg}, not {domains[0]}")
                        break

    # 4. Structure.
    if len(host.split(".")) > 4:
        flag(15, "Unusually many subdomains (often used to push the real domain out of view)")
    if reg_label.count("-") >= 2:
        flag(10, "Several hyphens in the domain name")
    tld = host.rsplit(".", 1)[-1]
    if tld in RISKY_TLDS:
        flag(10, f"'.{tld}' domains are cheap and common in phishing")
    if parts.port and parts.port not in (80, 443):
        flag(10, f"Uses an unusual port ({parts.port})")
    lure = next((w for w in LURE_WORDS if w in (host + (parts.path or "")).lower()), None)
    if lure and score > 0:
        flag(10, f"Uses a login/urgency word ('{lure}') alongside other warning signs")
    if scheme == "http" and lure:
        flag(10, "Asks for account details over an unencrypted (http) connection")
    if len(raw) > 200:
        flag(5, "Very long link")

    return _verdict(raw, host, reg, score, reasons)


def _verdict(url: str, host: str, reg: str, score: int, reasons: list) -> dict:
    level = "dangerous" if score >= 60 else "suspicious" if score >= 30 else "no_signs"
    return {"url": url, "host": host, "registered_domain": reg, "score": score,
            "verdict": level, "reasons": reasons}
