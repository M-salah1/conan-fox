#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WHOIS engine — the domain's registration record, over port 43.

A raw WHOIS query (RFC 3912): connect to the TLD's WHOIS server
on TCP port 43, send the domain, read the record, and follow the
"Whois Server:" referral to the registrar's server (max 3 hops).
Parsed fields only: registrar, registration / expiry / update
dates, nameservers, status, and the registrant ORGANIZATION name
when the record publishes one.

The raw record is never kept or shown: it can contain personal
contact data. Registrant e-mail, phone and postal address are
never collected — if the record redacts them, that is reported as
redacted, never bypassed. When port 43 is unreachable (some
networks block it), the engine reports an error and the RDAP-based
owner engine stays the fallback.
"""
import datetime
import re
import socket

NAME = "whois"
TITLE = "WHOIS (port 43)"

TLD_SERVERS = {
    "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
    "org": "whois.publicinterestregistry.org",
    "info": "whois.afilias.net", "biz": "whois.nic.biz",
    "io": "whois.nic.io", "co": "whois.nic.co",
    "me": "whois.nic.me", "ai": "whois.nic.ai",
    "app": "whois.nic.google", "dev": "whois.nic.google",
    "xyz": "whois.nic.xyz", "online": "whois.nic.online",
    "site": "whois.nic.site", "top": "whois.nic.top",
    "club": "whois.nic.club", "shop": "whois.nic.shop",
    "fr": "whois.nic.fr", "de": "whois.denic.de",
    "uk": "whois.nic.uk", "nl": "whois.domain-registry.nl",
    "dz": "whois.nic.dz", "ma": "whois.nic.ma",
    "tn": "whois.ati.tn", "eg": "whois.ripe.net",
    "us": "whois.nic.us", "ca": "whois.cira.ca",
    "au": "whois.auda.org.au", "jp": "whois.jprs.jp",
    "br": "whois.registro.br", "in": "whois.registry.in",
    "ru": "whois.tcinet.ru",
}

DATE_FORMATS = ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d", "%d-%b-%Y %H:%M:%S %Z", "%d-%b-%Y",
                "%d/%m/%Y", "%Y.%m.%d %H:%M:%S")


def _parse_date(raw):
    """Parse a WHOIS date string. Returns a datetime or None."""
    if not raw:
        return None
    s = raw.strip()
    m = re.search(r"(\d{4}-\d{2}-\d{2})", s)
    if m:
        try:
            return datetime.datetime.strptime(m.group(1), "%Y-%m-%d")
        except Exception:
            pass
    for fmt in DATE_FORMATS:
        try:
            return datetime.datetime.strptime(s, fmt)
        except Exception:
            continue
    return None


def _query(server, domain, timeout=8):
    """One WHOIS query. Returns the record text. Raises on failure."""
    sock = socket.create_connection((server, 43), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall((domain + "\r\n").encode())
        chunks = []
        total = 0
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            total += len(data)
            if total > 65536:
                break
        return b"".join(chunks).decode(errors="ignore")
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _field(lines, *needles):
    """First value whose key contains any needle (case-insensitive)."""
    for key, val in lines:
        lk = key.lower()
        if any(n in lk for n in needles):
            return val
    return None


def _parse(text):
    """Extract the public fields from a WHOIS record. Never returns
    raw text, e-mail addresses, phone numbers or postal addresses."""
    lines = []
    for line in (text or "").splitlines():
        line = line.strip()
        if ":" not in line or line.startswith("%"):
            continue
        key, val = line.split(":", 1)
        lines.append((key.strip(), val.strip()))
    out = {"registrar": None, "created": None, "expires": None,
           "updated": None, "nameservers": [], "status": [],
           "registrant_org": None, "whois_server": None}
    out["registrar"] = _field(lines, "registrar")
    if not out["registrar"]:
        out["registrar"] = _field(lines, "sponsoring registrar")
    created = _field(lines, "creation date", "created on",
                     "registered on", "registration date")
    expires = _field(lines, "expiry date", "expiration date",
                     "expire date", "registry expiry")
    updated = _field(lines, "updated date", "last updated")
    out["created"] = _parse_date(created)
    out["expires"] = _parse_date(expires)
    out["updated"] = _parse_date(updated)
    for key, val in lines:
        lk = key.lower()
        if lk in ("name server", "nameserver", "nserver") and val:
            ns = val.strip().rstrip(".").lower()
            if ns and ns not in out["nameservers"]:
                out["nameservers"].append(ns)
        elif lk == "domain status" and val:
            st = val.split()[0] if val.split() else val
            if st not in out["status"]:
                out["status"].append(st)
    org = _field(lines, "registrant organization",
                 "registrant organisation", "registrant org")
    if org and not re.search(r"redact|privacy|not disclosed",
                             org, re.I):
        out["registrant_org"] = org
    out["whois_server"] = _field(lines, "whois server")
    return out


def _fmt(dt):
    return dt.strftime("%Y-%m-%d") if dt else None


def run(ctx):
    domain = (ctx.get("domain") or "").lower().strip()
    data = {"domain": domain, "registrar": None, "registrant_org": None,
            "created": None, "expires": None, "days_left": None,
            "updated": None, "nameservers": [], "status": [],
            "whois_server": None, "hops": 0, "error": None}
    if not domain or "." not in domain or domain.startswith("127.") \
            or domain == "localhost":
        data["note"] = "Local test target — no public registration exists."
        return {"engine": NAME, "status": "completed",
                "findings": [], "data": data}
    tld = domain.rsplit(".", 1)[-1]
    server = TLD_SERVERS.get(tld)
    findings = []
    try:
        if not server:
            # Ask IANA which server holds this TLD.
            text = _query("whois.iana.org", tld)
            data["hops"] += 1
            server = _field([(l.split(":", 1)[0].strip(),
                              l.split(":", 1)[1].strip())
                             for l in text.splitlines() if ":" in l],
                            "whois")
        if not server:
            raise ValueError("no WHOIS server found for .%s" % tld)
        parsed = None
        for _hop in range(3):
            text = _query(server, domain)
            data["hops"] += 1
            parsed = _parse(text)
            data["whois_server"] = server
            nxt = parsed.get("whois_server")
            if nxt and nxt.lower() != server.lower():
                server = nxt
                continue
            break
        if not parsed:
            raise ValueError("empty WHOIS response")
    except Exception as exc:
        data["error"] = (
            "%s — WHOIS (TCP port 43) unreachable from here; the "
            "RDAP-based owner engine is the fallback" % str(exc)[:100])
        return {"engine": NAME, "status": "error",
                "findings": [], "data": data}
    data["registrar"] = parsed["registrar"]
    data["registrant_org"] = parsed["registrant_org"]
    data["created"] = _fmt(parsed["created"])
    data["expires"] = _fmt(parsed["expires"])
    data["updated"] = _fmt(parsed["updated"])
    data["nameservers"] = parsed["nameservers"]
    data["status"] = parsed["status"]
    if parsed["expires"]:
        data["days_left"] = (parsed["expires"]
                             - datetime.datetime.utcnow()).days
        if data["days_left"] < 0:
            findings.append({
                "severity": "critical",
                "name": "Domain registration EXPIRED",
                "evidence": "expired %s" % data["expires"],
                "fix": "Renew the domain registration immediately."})
        elif data["days_left"] < 30:
            findings.append({
                "severity": "medium",
                "name": "Domain registration expires soon",
                "evidence": "%d days left (expires %s)"
                            % (data["days_left"], data["expires"]),
                "fix": "Renew the domain registration before it "
                       "expires."})
    return {"engine": NAME, "status": "completed",
            "findings": findings, "data": data}
