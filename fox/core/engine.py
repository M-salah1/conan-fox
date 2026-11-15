#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FOX orchestrator — runs the engines as one investigation.

Waves (independent engines run in parallel inside each wave):
  1. crawl + web + tls + tech        (needs only the homepage)
  2. vuln + subdomains + history + wordpress + semgrep + secrets + shodan
  3. httpx                            (needs subdomains)
  4. network + fuzz                   (authorized targets only)

Every engine runs with its own deadline inside one global budget.
A fast-failing engine is retried once with backoff; a timeout is
never retried. The score is computed only from completed engines:
coverage below 50% means INCOMPLETE, never a misleading 0%.
"""
import concurrent.futures
import threading
import time

from ..core.http import get, lower_headers, request_retry, resolve_ips
from ..core.scope import normalize_url
from ..engines import BY_NAME, PROFILES

WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}

ENGINE_DEADLINES = {
    "web": 30, "crawl": 60, "tls": 30, "tech": 20, "vuln": 90,
    "subdomains": 60, "history": 30, "httpx": 60, "wordpress": 40,
    "semgrep": 60, "secrets": 40, "network": 90, "fuzz": 90,
    "shodan": 30,
}

PROFILE_BUDGETS = {"quick": 120, "deep": 240, "forensic": 600}


def call_with_timeout(fn, seconds):
    """Run fn in a daemon thread; return {"timed_out": True} on deadline."""
    result = {}

    def _run():
        try:
            result["value"] = fn()
        except Exception as exc:  # noqa: BLE001 - recorded, never raised
            result["error"] = str(exc)

    th = threading.Thread(target=_run, daemon=True)
    th.start()
    th.join(seconds)
    if th.is_alive():
        return {"timed_out": True, "error": "timeout after %ss" % seconds}
    if "error" in result:
        raise Exception(result["error"])
    return result.get("value")


def grade_for(score):
    if score is None:
        return "INCOMPLETE"
    if score >= 95:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def run_scan(url, profile="deep", scope=None, settings=None,
             progress=None):
    """Run one full FOX scan. Returns the scan dict."""
    settings = settings or {}
    url = normalize_url(url)
    host = url.split("/")[2] if "://" in url else url
    domain = host.split(":")[0]
    if domain.startswith("www."):
        domain = domain[4:]
    budget = int(settings.get("scan_budget_s",
                              PROFILE_BUDGETS.get(profile, 240)))
    deadlines = dict(ENGINE_DEADLINES)
    deadlines.update(settings.get("engine_deadlines") or {})
    t0 = time.time()

    def tick(name):
        if progress:
            try:
                progress(name)
            except Exception:
                pass

    def budget_left():
        return budget - (time.time() - t0)

    authorized = False
    if scope is not None:
        try:
            authorized = bool(scope.is_authorized(url))
        except Exception:
            authorized = False

    engines = PROFILES.get(profile, PROFILES["deep"])
    ctx = {"url": url, "host": host, "domain": domain,
           "authorized": authorized, "timeout": 8,
           "html": "", "headers": {}, "cookie_headers": [],
           "status": None, "ips": [], "pages": [], "scripts": [],
           "subdomains": []}
    results = {}
    status = {}

    # Homepage once, with retries; everything else builds on it.
    r = request_retry(url, timeout=10, attempts=3)
    ctx["status"] = r.get("status")
    ctx["html"] = r.get("body") or ""
    ctx["headers"] = lower_headers(r.get("headers") or {})
    try:
        ctx["cookie_headers"] = list(
            r.get("headers").get_all("Set-Cookie") or [])
    except Exception:
        ctx["cookie_headers"] = []
    ctx["ips"] = resolve_ips(domain if "." in domain else host)

    def _run_engine(name):
        """Run one engine with deadline + one fast-failure retry."""
        tick(name)
        started = time.time()
        attempts = 0
        while True:
            attempts += 1
            try:
                out = call_with_timeout(
                    lambda: BY_NAME[name].run(ctx), deadlines[name])
            except Exception as exc:
                out = {"engine": name, "status": "error",
                       "findings": [], "data": {"error": str(exc)}}
            if isinstance(out, dict) and out.get("timed_out"):
                status[name] = {"status": "timeout",
                                "duration_s": round(time.time() - started, 1),
                                "retries": attempts - 1,
                                "error": out.get("error", "")}
                return {"engine": name, "status": "timeout",
                        "findings": [], "data": {}}
            st = (out or {}).get("status", "completed")
            if st == "error" and attempts <= 1 \
                    and time.time() - started < 10:
                time.sleep(2)
                continue
            status[name] = {"status": st,
                            "duration_s": round(time.time() - started, 1),
                            "retries": attempts - 1,
                            "error": ((out or {}).get("data") or {})
                                     .get("error", "")}
            return out or {"engine": name, "status": st,
                           "findings": [], "data": {}}

    def _run_wave(names):
        """Run a wave in parallel; collect results as they finish."""
        todo = [n for n in names if n in engines and n not in results]
        if not todo or budget_left() <= 5:
            for n in todo:
                tick(n)
                status[n] = {"status": "timeout", "duration_s": 0,
                             "retries": 0, "error": "global budget reached"}
                results[n] = {"engine": n, "status": "timeout",
                              "findings": [], "data": {}}
            return
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=len(todo))
        try:
            futs = {pool.submit(_run_engine, n): n for n in todo}
            done, _ = concurrent.futures.wait(
                futs, timeout=budget_left(),
                return_when=concurrent.futures.ALL_COMPLETED)
            for fut, name in futs.items():
                if fut in done:
                    try:
                        results[name] = fut.result()
                    except Exception as exc:
                        results[name] = {"engine": name, "status": "error",
                                         "findings": [], "data": {}}
                        status[name] = {"status": "error", "duration_s": 0,
                                        "retries": 0, "error": str(exc)}
                else:
                    tick(name)
                    status[name] = {"status": "timeout",
                                    "duration_s": deadlines[name],
                                    "retries": 0,
                                    "error": "global budget reached"}
                    results[name] = {"engine": name, "status": "timeout",
                                     "findings": [], "data": {}}
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

    _run_wave(["crawl", "web", "tls", "tech"])
    crawl_data = (results.get("crawl") or {}).get("data") or {}
    ctx["pages"] = crawl_data.get("pages") or []
    ctx["scripts"] = crawl_data.get("scripts") or []
    _run_wave(["vuln", "subdomains", "history", "wordpress", "semgrep",
               "secrets", "shodan"])
    ctx["subdomains"] = ((results.get("subdomains") or {}).get("data") or {}) \
        .get("subdomains") or []
    _run_wave(["httpx"])
    _run_wave(["network", "fuzz"])

    # Findings, score, coverage — honest by construction.
    findings = []
    for name in engines:
        findings += (results.get(name) or {}).get("findings") or []
    completed = [n for n in engines
                 if status.get(n, {}).get("status") == "completed"]
    coverage = int(100 * len(completed) / max(1, len(engines)))
    reachable = ctx["status"] is not None
    if coverage < 50 or not reachable:
        # No site was measured (unreachable) or most engines failed:
        # the honest result is INCOMPLETE, never a score.
        score = None
    else:
        score = max(0, 100 - sum(WEIGHTS.get(f.get("severity"), 0)
                                 for f in findings))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f.get("severity"), 5))
    dist = {}
    for f in findings:
        dist[f["severity"]] = dist.get(f["severity"], 0) + 1
    duration = round(time.time() - t0, 1)
    scan = {
        "tool": "CONAN FOX v1.00", "target": url, "profile": profile,
        "kind": "fox-scan",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                    time.gmtime(time.time() - duration)),
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "duration_s": duration,
        "score": score, "grade": grade_for(score),
        "confidence": 88 if score is not None else 0,
        "coverage": {"completed": len(completed), "total": len(engines),
                     "percent": coverage,
                     "missing": [n for n in engines if n not in completed]},
        "engines": engines, "engine_status": status,
        "results": results, "findings": findings,
        "severity_distribution": dist,
        "recommendations": list(dict.fromkeys(
            f.get("fix", "") for f in findings if f.get("fix")))[:8],
        "scope": {"kind": "authorized" if authorized else "passive",
                  "authorized": authorized},
        "ips": ctx["ips"], "host": host, "domain": domain,
        "unreachable": not reachable,
    }
    return scan
