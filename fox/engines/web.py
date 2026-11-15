#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Web Scanner engine — OWASP ZAP style.

Passive analysis of the live HTTP response: security headers,
cookie flags, forms structure, HTTPS enforcement and mixed content.
Reads only — never submits a form, never logs in.
"""
import re

NAME = "web"
TITLE = "Web Scanner (ZAP)"

HEADER_CHECKS = [
    ("content-security-policy", "high",
     "Missing Content-Security-Policy",
     "Add a Content-Security-Policy header that only allows trusted sources."),
    ("strict-transport-security", "medium",
     "Missing Strict-Transport-Security (HSTS)",
     "Add Strict-Transport-Security: max-age=31536000; includeSubDomains."),
    ("x-frame-options", "medium",
     "Missing X-Frame-Options (clickjacking protection)",
     "Add X-Frame-Options: SAMEORIGIN (or frame-ancestors in CSP)."),
    ("x-content-type-options", "low",
     "Missing X-Content-Type-Options",
     "Add X-Content-Type-Options: nosniff."),
    ("referrer-policy", "low",
     "Missing Referrer-Policy",
     "Add Referrer-Policy: strict-origin-when-cross-origin."),
    ("permissions-policy", "low",
     "Missing Permissions-Policy",
     "Add a Permissions-Policy header disabling unused features."),
]


def _finding(sev, name, evidence, fix):
    return {"severity": sev, "name": name, "evidence": evidence, "fix": fix}


def run(ctx):
    if ctx.get("status") is None:
        # The site never answered: no header finding is real here.
        return {"engine": NAME, "status": "error",
                "findings": [],
                "data": {"error": "homepage unreachable"}}
    headers = ctx.get("headers") or {}
    html = ctx.get("html") or ""
    url = ctx.get("url") or ""
    findings = []
    data = {"headers_present": [], "headers_missing": [],
            "cookies": [], "forms": 0, "https": url.startswith("https://")}

    for name, sev, title, fix in HEADER_CHECKS:
        if name in headers:
            data["headers_present"].append(name)
        else:
            data["headers_missing"].append(name)
            findings.append(_finding(sev, title, "header %s absent" % name, fix))

    server = headers.get("server", "")
    if server and re.search(r"/\d", server):
        findings.append(_finding(
            "low", "Server version disclosed",
            "Server: %s" % server[:80],
            "Hide the version: ServerTokens Prod (Apache) or server_tokens off (Nginx)."))
        data["server_header"] = server
    powered = headers.get("x-powered-by", "")
    if powered:
        findings.append(_finding(
            "low", "Technology disclosed via X-Powered-By",
            "X-Powered-By: %s" % powered[:80],
            "Remove the X-Powered-By header."))
        data["x_powered_by"] = powered

    for raw in ctx.get("cookie_headers") or []:
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=")[0] if parts else ""
        flags = [p.lower() for p in parts[1:]]
        cookie = {"name": name,
                  "secure": any(p == "secure" for p in flags),
                  "httponly": any(p == "httponly" for p in flags),
                  "samesite": next((p.split("=", 1)[1] for p in flags
                                    if p.startswith("samesite")), None)}
        data["cookies"].append(cookie)
        if not cookie["secure"] and data["https"]:
            findings.append(_finding(
                "medium", "Cookie without Secure flag",
                "cookie %s" % name,
                "Set the Secure flag on every cookie."))
        if not cookie["httponly"]:
            findings.append(_finding(
                "medium", "Cookie without HttpOnly flag",
                "cookie %s" % name,
                "Set the HttpOnly flag so JavaScript cannot read the cookie."))
        if not cookie["samesite"]:
            findings.append(_finding(
                "low", "Cookie without SameSite attribute",
                "cookie %s" % name,
                "Set SameSite=Lax (or Strict) on cookies."))

    forms = re.findall(r"<form\b[^>]*>", html, re.I)
    data["forms"] = len(forms)
    for form in forms:
        if re.search(r"action\s*=\s*['\"]http://", form, re.I):
            findings.append(_finding(
                "high", "Form submits over plain HTTP",
                form[:120], "Submit every form over HTTPS only."))
            break
    if data["https"] and re.search(r'src\s*=\s*["\']http://', html, re.I):
        findings.append(_finding(
            "low", "Mixed content: HTTP resources on an HTTPS page",
            "http:// resource referenced",
            "Serve every resource (scripts, images, styles) over HTTPS."))
    if not data["https"]:
        findings.append(_finding(
            "high", "Site served over plain HTTP",
            url, "Redirect all traffic to HTTPS and enable HSTS."))

    return {"engine": NAME, "status": "completed",
            "findings": findings, "data": data}
