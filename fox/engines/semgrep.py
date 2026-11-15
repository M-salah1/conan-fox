#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JS Static Analysis engine — Semgrep style.

Fetches the site's public JavaScript files and matches them against
dangerous code patterns (eval, innerHTML sinks, document.write,
insecure randomness, hardcoded credential names). Static text
matching only — nothing is executed, values are never printed.
"""
import re

from ..core.http import get

NAME = "semgrep"
TITLE = "JS Static Analysis (Semgrep)"

# (pattern, severity, name, fix)
RULES = [
    (r"\beval\s*\(", "high", "Use of eval() in public JavaScript",
     "Remove eval(); use JSON.parse or safe alternatives."),
    (r"\.innerHTML\s*=", "medium", "innerHTML sink in public JavaScript",
     "Use textContent or a sanitizer before inserting HTML."),
    (r"document\.write\s*\(", "medium", "document.write() in public JavaScript",
     "Avoid document.write; build DOM nodes instead."),
    (r"Math\.random\(\)", "low", "Math.random() used (not cryptographic)",
     "Use crypto.getRandomValues() for tokens or secrets."),
    (r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"][^'\"]+",
     "high", "Hardcoded credential name in public JavaScript",
     "Move credentials to the server; never ship them in JS."),
    (r"localStorage\s*\[\s*['\"]password", "high",
     "Password stored in localStorage",
     "Never store passwords in localStorage."),
    (r"location\.href\s*=\s*[^;]*\+", "medium",
     "Open redirect pattern (location.href with concatenation)",
     "Validate redirect targets against an allow-list."),
    (r"\.outerHTML\s*=", "medium", "outerHTML sink in public JavaScript",
     "Use textContent or a sanitizer before inserting HTML."),
]


def run(ctx):
    if ctx.get("status") is None:
        return {"engine": NAME, "status": "error",
                "findings": [],
                "data": {"error": "homepage unreachable"}}
    findings = []
    checked = []
    scripts = ctx.get("scripts") or []
    if not scripts:
        # Fall back to script URLs found in the homepage HTML.
        scripts = re.findall(r'<script[^>]+src\s*=\s*["\']([^"\']+)',
                             ctx.get("html") or "", re.I)[:5]
    for url in scripts[:5]:
        if url.startswith("/"):
            url = (ctx.get("url") or "").rstrip("/") + url
        elif not url.startswith("http"):
            continue
        r = get(url, timeout=ctx.get("timeout", 8), max_bytes=200000)
        body = r.get("body") or ""
        if not body:
            continue
        checked.append(url)
        for pattern, sev, name, fix in RULES:
            try:
                m = re.search(pattern, body)
            except re.error:
                continue
            if m:
                findings.append({"severity": sev, "name": name,
                                 "evidence": "%s: pattern %r (line value "
                                             "redacted)" % (url[:80], name),
                                 "fix": fix})
    # De-duplicate by rule name.
    seen = set()
    unique = []
    for f in findings:
        if f["name"] not in seen:
            seen.add(f["name"])
            unique.append(f)
    return {"engine": NAME, "status": "completed",
            "findings": unique,
            "data": {"checked": checked, "rules": len(RULES),
                     "hits": len(unique)}}
