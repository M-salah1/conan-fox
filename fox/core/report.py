#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FOX reports: terminal, JSON and HTML.

Every report shows the same honest picture: score (or INCOMPLETE),
coverage, per-engine status, unified findings with evidence and fix,
and recommendations. Secret values never appear — engines only
record names, flags and redacted evidence.
"""
import html as html_mod
import json

from .i18n import t

SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def score_line(scan, lang):
    if scan.get("score") is None:
        return "%s: %s   %s: %s   %s: %s%%   %s: %s s" % (
            t(lang, "score"), t(lang, "incomplete"),
            t(lang, "grade"), t(lang, "incomplete"),
            t(lang, "coverage"),
            (scan.get("coverage") or {}).get("percent", 0),
            t(lang, "duration"), scan.get("duration_s"))
    return "%s: %s%%   %s: %s   %s: %s%%   %s: %s%%   %s: %s s" % (
        t(lang, "score"), scan.get("score"),
        t(lang, "grade"), scan.get("grade"),
        t(lang, "confidence"), scan.get("confidence"),
        t(lang, "coverage"), (scan.get("coverage") or {}).get("percent", 0),
        t(lang, "duration"), scan.get("duration_s"))


def print_report(scan, lang="ar"):
    print("=" * 60)
    print("🦊 CONAN FOX v1.00 — %s" % t(lang, "report"))
    print("%s: %s" % (t(lang, "target"), scan.get("target")))
    print("%s: %s" % (t(lang, "profile"), scan.get("profile")))
    print(score_line(scan, lang))
    dist = scan.get("severity_distribution") or {}
    print("%s: %s" % (t(lang, "findings"),
                      ", ".join("%s=%d" % (k, v) for k, v in dist.items()
                                if v) or "0"))
    print("=" * 60)
    print("%s:" % t(lang, "engine_status"))
    for name in scan.get("engines") or []:
        run = (scan.get("engine_status") or {}).get(name) or {}
        line = "  • %s: %s (%ss" % (name, run.get("status"),
                                   run.get("duration_s"))
        if run.get("retries"):
            line += ", %d retries" % run["retries"]
        if run.get("error"):
            line += " — %s" % str(run["error"])[:70]
        print(line + ")")
    for name in scan.get("engines") or []:
        res = (scan.get("results") or {}).get(name) or {}
        if res.get("status") != "completed":
            continue
        print("-" * 60)
        print("Engine: %s" % name)
        for key, val in (res.get("data") or {}).items():
            if key in ("checked", "results", "pages", "scripts", "urls",
                       "hosts", "subdomains", "open_ports", "checked"):
                if isinstance(val, list):
                    print("  %s: %d items" % (key, len(val)))
                else:
                    print("  %s: %s" % (key, val))
            elif isinstance(val, (str, int, float, bool)) or val is None:
                print("  %s: %s" % (key, val))
        for f in res.get("findings") or []:
            print("  [%s] %s" % (f["severity"].upper(), f["name"]))
            print("      %s" % f.get("evidence", "")[:160])
    print("=" * 60)
    print("%s:" % t(lang, "recommendations"))
    for fix in (scan.get("recommendations") or [])[:8]:
        print("  • %s" % fix)
    print("=" * 60)


def to_json(scan, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(scan, f, ensure_ascii=False, indent=2)
    return path


def to_html(scan, path):
    def esc(v):
        return html_mod.escape(str(v))
    rows = ""
    for f in scan.get("findings") or []:
        rows += ("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
                 % (esc(f.get("severity", "")), esc(f.get("name", "")),
                    esc(f.get("evidence", "")[:200]),
                    esc(f.get("fix", "")[:200])))
    engines = ""
    for name in scan.get("engines") or []:
        run = (scan.get("engine_status") or {}).get(name) or {}
        engines += "<li>%s: %s (%ss)</li>" % (esc(name),
                                              esc(run.get("status", "")),
                                              esc(run.get("duration_s", "")))
    score = scan.get("score")
    score_txt = "INCOMPLETE" if score is None else "%s%% (%s)" % (
        score, scan.get("grade"))
    doc = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>CONAN FOX Report — %s</title>
<style>body{font-family:sans-serif;margin:2em}table{border-collapse:collapse}
td,th{border:1px solid #ccc;padding:6px;text-align:left}</style></head>
<body><h1>🦊 CONAN FOX v1.00 — %s</h1>
<p><b>Target:</b> %s &nbsp; <b>Profile:</b> %s &nbsp; <b>Score:</b> %s
&nbsp; <b>Coverage:</b> %s%% &nbsp; <b>Duration:</b> %s s</p>
<h2>Engines</h2><ul>%s</ul>
<h2>Findings</h2><table><tr><th>Severity</th><th>Finding</th>
<th>Evidence</th><th>Fix</th></tr>%s</table>
<h2>Recommendations</h2><ul>%s</ul>
<p>CONAN FOX v1.00 — FOX COMPANY — Developer: Hafed Mehdi Salah Eddine</p>
</body></html>""" % (
        esc(scan.get("target")), esc(scan.get("target")),
        esc(scan.get("target")), esc(scan.get("profile")), esc(score_txt),
        esc((scan.get("coverage") or {}).get("percent", 0)),
        esc(scan.get("duration_s")), engines, rows,
        "".join("<li>%s</li>" % esc(x)
                for x in scan.get("recommendations") or []))
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
    return path
