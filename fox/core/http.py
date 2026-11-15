#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared HTTP + DNS layer for every FOX engine.

One place for: plain requests (never raises), DNS-over-HTTPS,
hostname resolution, retries with exponential backoff, and the
public JSON fetchers (CT log, Wayback, Shodan) used by engines.
"""
import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) ConanFox/1.00 Chrome/120.0 Safari/537.36")
DOH_URL = "https://dns.google/resolve"


def request(url, method="GET", headers=None, timeout=10, max_bytes=200000,
            data=None):
    """One HTTP request. Never raises. Returns a dict."""
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(max_bytes).decode(errors="ignore")
            return {"status": resp.status, "final_url": resp.geturl(),
                    "headers": resp.headers, "body": body,
                    "error": None,
                    "elapsed_ms": int((time.time() - t0) * 1000)}
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(max_bytes).decode(errors="ignore")
        except Exception:
            body = ""
        return {"status": exc.code, "final_url": exc.geturl(),
                "headers": exc.headers or {}, "body": body,
                "error": "HTTP %s" % exc.code,
                "elapsed_ms": int((time.time() - t0) * 1000)}
    except Exception as exc:
        return {"status": None, "final_url": url, "headers": {}, "body": "",
                "chain": [], "error": str(exc),
                "elapsed_ms": int((time.time() - t0) * 1000)}


def get(url, timeout=10, max_bytes=200000):
    return request(url, timeout=timeout, max_bytes=max_bytes)


def request_retry(url, timeout=10, attempts=3, max_bytes=200000):
    """GET with exponential backoff on fast network failures only."""
    last = None
    for i in range(attempts):
        last = get(url, timeout=timeout, max_bytes=max_bytes)
        if last.get("status") is not None or "timed out" in (
                last.get("error") or ""):
            return last
        time.sleep(1 * (2 ** i))
    return last


def fetch_json(url, timeout=12, max_bytes=500000):
    """GET + JSON parse. Returns (data, error). Never raises."""
    r = get(url, timeout=timeout, max_bytes=max_bytes)
    if r.get("status") != 200 or not r.get("body"):
        return None, (r.get("error") or "HTTP %s" % r.get("status"))
    try:
        return json.loads(r["body"]), None
    except Exception as exc:
        return None, str(exc)


def doh(domain, rtype="A", timeout=8):
    """DNS-over-HTTPS records for one type. Returns a list of strings."""
    q = "%s?name=%s&type=%s" % (DOH_URL, urllib.parse.quote(domain), rtype)
    data, _err = fetch_json(q, timeout=timeout, max_bytes=100000)
    if not data:
        return []
    out = []
    for ans in data.get("Answer") or []:
        val = str(ans.get("data", "")).strip().strip('"')
        if val:
            out.append(val)
    return out


def resolve_ips(host, timeout=8):
    """All A/AAAA addresses for a host (DoH first, system DNS fallback)."""
    ips = []
    for t in ("A", "AAAA"):
        for ip in doh(host, t, timeout=timeout):
            if ip not in ips:
                ips.append(ip)
    if not ips:
        try:
            _h, _a, addr = socket.gethostbyname_ex(host)
            for ip in addr:
                if ip not in ips:
                    ips.append(ip)
        except Exception:
            pass
    return ips


def lower_headers(headers):
    try:
        return {str(k).lower(): v for k, v in dict(headers).items()}
    except Exception:
        return {}


def get_set_cookie_headers(headers):
    """All raw Set-Cookie header values from a response's headers.

    headers may be an HTTPMessage (get_all), a dict, or {}.
    Returns a list of strings (possibly empty). Never raises.
    """
    if headers is None:
        return []
    try:
        vals = headers.get_all("Set-Cookie")
        if vals:
            return list(vals)
    except Exception:
        pass
    try:
        out = []
        for k, v in dict(headers).items():
            if str(k).lower() == "set-cookie":
                if isinstance(v, (list, tuple)):
                    out.extend(str(x) for x in v)
                else:
                    out.append(str(v))
        return out
    except Exception:
        return []


def parse_set_cookie(raw):
    """Parse one Set-Cookie header into a value-free record.

    The cookie VALUE is never kept: a value is a session secret, and
    a displayed value is a leaked value. The record carries the name,
    the flags and the attributes only.
    """
    parts = [p.strip() for p in (raw or "").split(";")]
    name = parts[0].split("=")[0].strip() if parts and parts[0] else ""
    flags = [p.lower() for p in parts[1:]]

    def _attr(attr):
        for p in flags:
            if p.startswith(attr + "="):
                return p.split("=", 1)[1].strip()
        return None

    expires = _attr("expires")
    max_age = _attr("max-age")
    return {"name": name,
            "secure": "secure" in flags,
            "httponly": "httponly" in flags,
            "samesite": _attr("samesite"),
            "domain": _attr("domain"), "path": _attr("path"),
            "expires": expires, "max_age": max_age,
            "session": expires is None and max_age is None}
