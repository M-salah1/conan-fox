#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Vulnerability Detection engine — Nuclei / Nikto style.

Template-based checks: each template is one read-only GET request
against a well-known path, matched against the real response.
No payloads, no exploitation, no login — a 200 on /.git/HEAD only
proves the file is public, and the fix tells the owner how to close it.
"""
from ..core.http import request

NAME = "vuln"
TITLE = "Vulnerability Detection (Nuclei)"

# (path, severity, name, match, fix)
# match: "status200" | "status200+marker:TEXT" | "status401or403"
TEMPLATES = [
    ("/.git/HEAD", "high", "Git repository exposed (.git/HEAD is public)",
     "status200+marker:ref:", "Block access to /.git/ on the web server."),
    ("/.env", "critical", "Environment file exposed (.env is public)",
     "status200+marker:=", "Move .env outside the web root; block dotfiles."),
    ("/.env.bak", "high", "Backup environment file exposed",
     "status200", "Delete backup files from the web root."),
    ("/wp-config.php", "high", "WordPress config exposed",
     "status200+marker:DB_", "Block access to wp-config.php."),
    ("/config.php", "medium", "Config file publicly readable",
     "status200+marker:<?php", "Block direct access to config files."),
    ("/backup.zip", "high", "Backup archive publicly downloadable",
     "status200", "Move backups outside the web root."),
    ("/db.sql", "high", "Database dump publicly downloadable",
     "status200", "Move database dumps outside the web root."),
    ("/phpinfo.php", "medium", "phpinfo() page exposed",
     "status200+marker:PHP Version", "Remove phpinfo pages from production."),
    ("/server-status", "medium", "Apache server-status exposed",
     "status200+marker:Apache Server Status",
     "Restrict /server-status to localhost only."),
    ("/.DS_Store", "low", "macOS metadata file exposed",
     "status200", "Delete .DS_Store files from the web root."),
    ("/.svn/entries", "medium", "Subversion metadata exposed",
     "status200", "Block access to /.svn/ on the web server."),
    ("/api/docs", "low", "API documentation publicly exposed",
     "status200", "Protect API docs behind authentication if they are internal."),
    ("/swagger.json", "low", "OpenAPI definition publicly exposed",
     "status200+marker:openapi", "Protect API definitions if they are internal."),
    ("/admin", "low", "Admin panel reachable without prior check",
     "status200", "Protect /admin with strong authentication and rate limiting."),
    ("/.well-known/security.txt", "info", "security.txt present (good practice)",
     "status200+marker:Contact:", "Keep security.txt up to date."),
    ("/robots.txt", "info", "robots.txt present",
     "status200", "Check robots.txt does not list sensitive paths."),
]


def _match(template_match, r):
    if template_match.startswith("status200+marker:"):
        marker = template_match.split(":", 1)[1]
        return r.get("status") == 200 and marker in (r.get("body") or "")
    if template_match == "status200":
        return r.get("status") == 200
    return False


def run(ctx):
    base = (ctx.get("url") or "").rstrip("/")
    timeout = ctx.get("timeout", 8)
    findings = []
    checked = []
    for path, sev, name, match, fix in TEMPLATES:
        r = request(base + path, timeout=timeout, max_bytes=20000)
        checked.append({"path": path, "status": r.get("status")})
        if _match(match, r):
            findings.append({
                "severity": sev, "name": name,
                "evidence": "%s -> HTTP %s" % (path, r.get("status")),
                "fix": fix})
    return {"engine": NAME, "status": "completed",
            "findings": findings,
            "data": {"templates": len(TEMPLATES), "checked": checked,
                     "hits": len(findings)}}
