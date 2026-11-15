#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Path Fuzzing engine — FFUF style.

Bounded parallel wordlist probing of public paths. Each answer is
recorded with its real status and size; interesting statuses
(200/301/401/403) are flagged. Authorized targets only, rate-limited
by the worker count.
"""
import concurrent.futures

from ..core.http import request

NAME = "fuzz"
TITLE = "Path Fuzzer (FFUF)"

WORDLIST = [
    "/robots.txt", "/sitemap.xml", "/security.txt",
    "/.well-known/security.txt", "/admin", "/login", "/register",
    "/signup", "/dashboard", "/api", "/api/docs", "/swagger.json",
    "/openapi.json", "/.git/HEAD", "/.env", "/wp-admin", "/wp-login.php",
    "/wp-config.php", "/config.php", "/backup.zip", "/db.sql",
    "/.env.bak", "/sitemap_index.xml", "/about", "/contact", "/privacy",
    "/terms", "/feed", "/rss.xml", "/static", "/assets", "/uploads",
    "/images", "/css", "/js", "/health", "/status", "/metrics",
    "/.well-known/robots.txt", "/.htaccess", "/crossdomain.xml",
    "/clientaccesspolicy.xml", "/.git/config", "/.svn/entries",
    "/.DS_Store", "/phpinfo.php", "/server-status", "/.bash_history",
    "/web.config", "/composer.json", "/package.json", "/.npmrc",
    "/.dockerignore", "/Dockerfile", "/.gitlab-ci.yml", "/.travis.yml",
    "/README.md", "/CHANGELOG.md", "/LICENSE", "/.idea/", "/.vscode/",
    "/debug", "/test", "/old", "/bak", "/backup", "/tmp",
]


def _probe(base, path, timeout):
    r = request(base + path, timeout=timeout, max_bytes=5000)
    return {"path": path, "status": r.get("status"),
            "size": len(r.get("body") or ""), "error": r.get("error")}


def run(ctx):
    if not ctx.get("authorized"):
        return {"engine": NAME, "status": "not_tested",
                "findings": [], "data": {"note": "needs authorization"}}
    base = (ctx.get("url") or "").rstrip("/")
    timeout = min(ctx.get("timeout", 8), 8)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futs = {pool.submit(_probe, base, p, timeout): p for p in WORDLIST}
        for fut in futs:
            try:
                results.append(fut.result(timeout=timeout + 5))
            except Exception as exc:
                results.append({"path": futs[fut], "status": None,
                                "size": 0, "error": str(exc)})
    interesting = [e for e in results
                   if e.get("status") in (200, 301, 302, 401, 403)]
    findings = []
    for e in interesting:
        if e["path"] in ("/.git/HEAD", "/.env", "/wp-config.php",
                         "/backup.zip", "/db.sql", "/.git/config"):
            findings.append({
                "severity": "high",
                "name": "Sensitive path publicly reachable: %s" % e["path"],
                "evidence": "%s -> HTTP %s" % (e["path"], e["status"]),
                "fix": "Remove or block %s on the web server." % e["path"]})
    return {"engine": NAME, "status": "completed", "findings": findings,
            "data": {"probed": len(results), "interesting": interesting,
                     "results": results}}
