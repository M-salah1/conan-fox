#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CONAN FOX v1.00 — entry point.

Terminal console (Arabic / French / English) + direct scan mode.
    python3 fox.py                  # console
    python3 fox.py https://example.com
    python3 fox.py https://example.com --profile forensic --json out.json
"""
import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fox import __version__  # noqa: E402
from fox.core import engine as engine_mod  # noqa: E402
from fox.core import report as report_mod  # noqa: E402
from fox.core import storage as storage_mod  # noqa: E402
from fox.core.i18n import t  # noqa: E402
from fox.core.scope import Scope, normalize_url, valid_url  # noqa: E402
from fox.engines import PROFILES  # noqa: E402

SETTINGS_FILE = "fox-settings.json"
DB_FILE = "fox-scans.db"

FOX_BANNER = r"""
   /\   /\
  (  o   o  )
   (   =^=   )
    (       )
     |  |  |
  🦊 CONAN FOX v%s — FOX COMPANY
"""


def load_settings():
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"language": "ar", "profile": "deep"}


def save_settings(settings):
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(settings, f, ensure_ascii=False)
    except Exception:
        pass


def choose_language():
    print("1. العربية    2. English    3. Français")
    try:
        choice = input("> ").strip()
    except (EOFError, KeyboardInterrupt):
        return "ar"
    return {"1": "ar", "2": "en", "3": "fr"}.get(choice, "ar")


class Spinner:
    """One-line loader: spinner + current engine + % + elapsed."""

    SPINNER = ["◐", "◓", "◑", "◒"]

    def __init__(self, total, lang):
        self.total = max(1, total)
        self.done = set()
        self.current = ""
        self.lang = lang
        self.started = time.time()
        self.stop = False
        self.thread = None

    def progress(self, name):
        self.done.add(name)
        self.current = name

    def _run(self):
        frame = 0
        while not self.stop:
            spin = self.SPINNER[frame % len(self.SPINNER)]
            pct = min(99, int(100 * len(self.done) / self.total))
            elapsed = int(time.time() - self.started)
            line = "\r%s %s %d%%" % (spin, t(self.lang, "scanning"), pct)
            if self.current:
                line += " — %s" % self.current[:24]
            line += " %ds" % elapsed
            sys.stdout.write(line)
            sys.stdout.flush()
            time.sleep(0.12)
            frame += 1

    def start(self):
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def finish(self, duration):
        self.stop = True
        if self.thread:
            self.thread.join(timeout=1)
        sys.stdout.write("\r%s %s %.1fs — %d/%d %s\n" % (
            "✓", t(self.lang, "done"), duration, len(self.done),
            self.total, t(self.lang, "phases")))
        sys.stdout.flush()


def accept_terms(lang, scope, url):
    print("=" * 60)
    print("  ⚖  %s" % t(lang, "terms_title"))
    for i in range(1, 5):
        print("   • %s" % t(lang, "terms_%d" % i))
    print("=" * 60)
    try:
        ans = input("%s " % t(lang, "terms_accept")).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    if ans != "y":
        print(t(lang, "terms_declined"))
        return False
    print(t(lang, "terms_accepted"))
    return True


def ask_authorization(lang, scope, url):
    if scope.is_authorized(url):
        return True
    print(t(lang, "auth_needed"))
    try:
        ans = input("%s " % t(lang, "auth_question")).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    if ans == "y":
        scope.authorize(url)
        return True
    return False


def do_scan(url, profile, lang, scope, settings):
    url = normalize_url(url)
    if not valid_url(url):
        print(t(lang, "invalid_url"))
        return None
    if not accept_terms(lang, scope, url):
        return None
    # Active engines (network + fuzz) need authorization; ask once.
    needs_auth = profile in ("deep", "forensic")
    if needs_auth and not scope.is_authorized(url):
        if ask_authorization(lang, scope, url):
            pass  # authorized now; passive run continues either way
    total = len(PROFILES[profile])
    spin = Spinner(total, lang)
    spin.start()
    try:
        scan = engine_mod.run_scan(url, profile=profile, scope=scope,
                                   settings=settings,
                                   progress=spin.progress)
    finally:
        spin.finish(scan["duration_s"] if "scan" in dir() else 0)
    report_mod.print_report(scan, lang)
    try:
        scan_id = storage_mod.save_scan(DB_FILE, scan)
        scan["scan_id"] = scan_id
    except Exception:
        pass
    return scan


def dashboard(scan, lang):
    while True:
        print("-" * 60)
        print("0. %s    1. %s    2. JSON    3. HTML" % (
            t(lang, "back"), t(lang, "findings")))
        try:
            choice = input("%s " % t(lang, "enter_choice")).strip()
        except (EOFError, KeyboardInterrupt):
            return
        if choice == "0" or choice == "":
            return
        if choice == "1":
            for f in scan.get("findings") or []:
                print("  [%s] %s" % (f["severity"].upper(), f["name"]))
                print("      %s" % f.get("evidence", "")[:180])
                print("      Fix: %s" % f.get("fix", "")[:180])
        elif choice == "2":
            path = report_mod.to_json(scan, "fox-report.json")
            print("Saved: %s" % path)
        elif choice == "3":
            path = report_mod.to_html(scan, "fox-report.html")
            print("Saved: %s" % path)


def show_history(lang):
    rows = storage_mod.list_scans(DB_FILE)
    print("=" * 60)
    print("🦊 %s" % t(lang, "history"))
    if not rows:
        print(t(lang, "no_history"))
        return
    for r in rows:
        score = r["score"] if r["score"] is not None else "INCOMPLETE"
        print("#%s  %s  [%s]  score=%s  grade=%s  coverage=%s%%  %s" % (
            r["id"], r["target"], r["profile"], score, r["grade"],
            r["coverage"], r["finished_at"] or ""))


def print_help(lang):
    print("=" * 60)
    print("🦊 %s" % t(lang, "help_title"))
    print("  scan <url>      — %s" % t(lang, "help_scan"))
    print("  profile <name>  — %s (quick / deep / forensic)" % t(lang, "help_profile"))
    print("  history         — %s" % t(lang, "help_history"))
    print("  lang            — %s" % t(lang, "help_lang"))
    print("  help            — %s" % t(lang, "help_title"))
    print("  exit / 0        — %s" % t(lang, "help_exit"))
    print("=" * 60)


def console():
    settings = load_settings()
    print(FOX_BANNER % __version__)
    print(t("ar", "choose_language"))
    lang = choose_language()
    settings["language"] = lang
    save_settings(settings)
    profile = settings.get("profile", "deep")
    scope = Scope()
    print("%s — %s" % (t(lang, "app_subtitle"), t(lang, "org")))
    print(t(lang, "developer"))
    print(t(lang, "welcome"))
    print(t(lang, "how_to"))
    print("profile: %s" % profile)
    while True:
        try:
            raw = input("\nfox > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n%s" % t(lang, "goodbye"))
            return
        if not raw:
            continue
        parts = raw.split(None, 1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""
        if cmd in ("exit", "quit", "0"):
            print(t(lang, "goodbye"))
            return
        if cmd == "help":
            print_help(lang)
        elif cmd == "lang":
            lang = choose_language()
            settings["language"] = lang
            save_settings(settings)
            print("Language: %s" % lang)
        elif cmd == "profile":
            if arg in PROFILES:
                profile = arg
                settings["profile"] = profile
                save_settings(settings)
                print("profile: %s" % profile)
            else:
                print("quick / deep / forensic")
        elif cmd == "history":
            show_history(lang)
        elif cmd == "scan":
            if not arg:
                try:
                    arg = input("%s " % t(lang, "enter_url")).strip()
                except (EOFError, KeyboardInterrupt):
                    continue
            scan = do_scan(arg, profile, lang, scope, settings)
            if scan:
                dashboard(scan, lang)
        elif valid_url(normalize_url(raw)):
            scan = do_scan(raw, profile, lang, scope, settings)
            if scan:
                dashboard(scan, lang)
        else:
            print(t(lang, "unknown_command"))


def main(argv):
    if "--version" in argv:
        print("CONAN FOX v%s" % __version__)
        return 0
    settings = load_settings()
    lang = settings.get("language", "ar")
    profile = settings.get("profile", "deep")
    url = None
    json_out = None
    html_out = None
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--profile" and i + 1 < len(argv):
            profile = argv[i + 1]
            i += 2
        elif a == "--lang" and i + 1 < len(argv):
            lang = argv[i + 1]
            i += 2
        elif a == "--json" and i + 1 < len(argv):
            json_out = argv[i + 1]
            i += 2
        elif a == "--html" and i + 1 < len(argv):
            html_out = argv[i + 1]
            i += 2
        elif not a.startswith("-"):
            url = a
            i += 1
        else:
            i += 1
    if profile not in PROFILES:
        profile = "deep"
    if not url:
        console()
        return 0
    scope = Scope()
    url = normalize_url(url)
    if not valid_url(url):
        print(t(lang, "invalid_url"))
        return 2
    scan = engine_mod.run_scan(url, profile=profile, scope=scope,
                               settings=settings)
    report_mod.print_report(scan, lang)
    try:
        storage_mod.save_scan(DB_FILE, scan)
    except Exception:
        pass
    if json_out:
        print("Saved: %s" % report_mod.to_json(scan, json_out))
    if html_out:
        print("Saved: %s" % report_mod.to_html(scan, html_out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
