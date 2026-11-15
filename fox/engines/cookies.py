#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cookies engine — fetch every cookie the site sets, on every page.

The homepage sets cookies, but so do login pages, forms and
redirects: this engine inventories Set-Cookie headers from the
homepage AND from every page the crawler visited, and checks each
cookie's flags (Secure, HttpOnly, SameSite), lifetime and
first-party / third-party origin.

The cookie VALUE is never collected, shown or stored — a value is
a session secret, and a displayed value is a leaked value. Only
the name, the flags and the attributes are recorded. To check
whether a value you own appears anywhere public, use Verify
(dashboard option 4): type it hidden, get YES/NO + location only.
"""
import datetime
import urllib.parse

from ..core.http import get_set_cookie_headers, parse_set_cookie

NAME = "cookies"
TITLE = "Cookies (full-site inventory)"

LONG_LIVED_DAYS = 365


def _long_lived(rec):
    """True when a persistent cookie lives longer than a year."""
    try:
        if rec.get("max_age") is not None \
                and int(rec["max_age"]) > LONG_LIVED_DAYS * 86400:
            return True
    except Exception:
        pass
    exp = rec.get("expires")
    if exp:
        try:
            d = datetime.datetime.strptime(
                exp, "%a, %d %b %Y %H:%M:%S %Z")
            if (d - datetime.datetime.utcnow()).days \
                    > LONG_LIVED_DAYS:
                return True
        except Exception:
            pass
    return False


def _is_third_party(domain, host):
    if not domain:
        return False
    d = domain.lstrip(".").lower()
    h = (host or "").lower()
    return d != h and not h.endswith("." + d) and not d.endswith("." + h)


def run(ctx):
    if ctx.get("status") is None:
        return {"engine": NAME, "status": "error",
                "findings": [],
                "data": {"error": "homepage unreachable"}}
    host = ctx.get("host") or ""
    url = ctx.get("url") or ""
    https = url.startswith("https://")
    try:
        home_path = urllib.parse.urlparse(url).path or "/"
    except Exception:
        home_path = "/"

    records = []
    for raw in ctx.get("cookie_headers") or []:
        rec = parse_set_cookie(raw)
        if rec["name"]:
            rec["page"] = home_path
            records.append(rec)
    for rec in ctx.get("crawl_cookies") or []:
        if isinstance(rec, dict) and rec.get("name"):
            records.append(dict(rec))

    for rec in records:
        rec["third_party"] = _is_third_party(rec.get("domain"), host)
        # Normalize the page to its path, then drop exact duplicates:
        # the homepage cookie also appears in the crawl (the crawler
        # visits the homepage too) and must be counted once.
        try:
            rec["page"] = urllib.parse.urlparse(
                rec.get("page") or "/").path or "/"
        except Exception:
            rec["page"] = rec.get("page") or "/"
    unique = []
    seen_rec = set()
    for rec in records:
        key = (rec["name"], rec.get("domain"), rec.get("path"),
               rec.get("page"))
        if key in seen_rec:
            continue
        seen_rec.add(key)
        unique.append(rec)
    records = unique

    findings = []
    seen = set()

    def _add(sev, kind, name, rec, fix):
        key = (name, kind)
        if key in seen:
            return
        seen.add(key)
        findings.append({"severity": sev,
                         "name": "Cookie '%s' %s" % (name, kind),
                         "evidence": "cookie %s (page %s)"
                                     % (name, rec.get("page") or "/"),
                         "fix": fix})

    for rec in records:
        name = rec["name"]
        if not rec["secure"] and https:
            _add("medium", "has no Secure flag", name, rec,
                 "Set the Secure flag so the cookie is only sent over "
                 "HTTPS.")
        if not rec["httponly"]:
            _add("medium", "has no HttpOnly flag", name, rec,
                 "Set the HttpOnly flag so JavaScript cannot read the "
                 "cookie.")
        if not rec["samesite"]:
            _add("low", "has no SameSite attribute", name, rec,
                 "Set SameSite=Lax (or Strict) on the cookie.")
        if rec["third_party"]:
            _add("info", "is a third-party cookie", name, rec,
                 "Check whether the third-party cookie is needed; "
                 "remove it if not.")
        if not rec["session"] and _long_lived(rec):
            _add("low", "is long-lived (over a year)", name, rec,
                 "Shorten the cookie lifetime; long-lived cookies "
                 "extend the window of a stolen session.")

    data = {"cookies": records, "total": len(records),
            "pages_with_cookies": len({r.get("page") for r in records}),
            "without_secure": sum(1 for r in records
                                  if not r["secure"] and https),
            "without_httponly": sum(1 for r in records
                                    if not r["httponly"]),
            "without_samesite": sum(1 for r in records
                                    if not r["samesite"]),
            "third_party": sum(1 for r in records if r["third_party"]),
            "https": https}
    return {"engine": NAME, "status": "completed",
            "findings": findings, "data": data}
