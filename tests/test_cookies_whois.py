#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CONAN FOX NOVA v2.30 tests — cookies engine + WHOIS engine.

The user asked for both: cookies fetched from every page the site
sets them on, and real WHOIS (port 43) instead of RDAP only.
Cookie VALUES are never collected, shown or stored — the tests
assert the lab value "abc123" never appears in any output.
"""
import datetime
import json
import os
import socket
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fox.core import validator as validator_mod
from fox.core.http import get_set_cookie_headers, parse_set_cookie
from fox.engines import cookies, crawl, whois
from tests.test_fox import Lab, lab_ctx


class FakeSocket:
    """A socket that answers one canned WHOIS response, then EOF."""

    def __init__(self, text):
        self._chunks = [text.encode(), b""]
        self.sent = b""

    def settimeout(self, _t):
        pass

    def sendall(self, data):
        self.sent += data

    def recv(self, _n):
        return self._chunks.pop(0) if self._chunks else b""

    def close(self):
        pass


REGISTRAR_RECORD = """Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar: Example Registrar, Inc.
Registrar IANA ID: 123
Registrar Abuse Contact Email: abuse@example-registrar.com
Registrant Organization: Example Org
Registrant Email: hidden@example.com
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2027-08-13T04:00:00Z
Updated Date: 2024-08-14T04:00:00Z
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
"""

THIN_RECORD = """Domain Name: EXAMPLE.COM
Registrar: Example Registrar, Inc.
Whois Server: whois.registrar-example.com
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2027-08-13T04:00:00Z
Name Server: A.IANA-SERVERS.NET
"""

IANA_RECORD = """% IANA WHOIS server

domain:       ABCXYZ

whois:        whois.nic.abcxyz

"""


def _whois_ctx(domain="example.com"):
    return {"url": "https://%s/" % domain, "host": domain,
            "domain": domain, "authorized": False, "timeout": 5,
            "html": "", "headers": {}, "cookie_headers": [],
            "status": 200, "ips": [], "pages": [], "scripts": [],
            "subdomains": []}


class TestParseCookie(unittest.TestCase):
    def test_value_never_kept(self):
        rec = parse_set_cookie(
            "lab_session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax")
        self.assertEqual(rec["name"], "lab_session")
        self.assertTrue(rec["secure"])
        self.assertTrue(rec["httponly"])
        self.assertEqual(rec["samesite"], "lax")
        self.assertTrue(rec["session"])
        self.assertNotIn("abc123", json.dumps(rec))

    def test_persistent_cookie(self):
        rec = parse_set_cookie(
            "tracker=xyz; Domain=.tracker.com; Max-Age=63072000")
        self.assertEqual(rec["domain"], ".tracker.com")
        self.assertEqual(rec["max_age"], "63072000")
        self.assertFalse(rec["session"])

    def test_raw_header_extraction(self):
        self.assertEqual(
            get_set_cookie_headers({"Set-Cookie": "a=1; Path=/"}),
            ["a=1; Path=/"])
        self.assertEqual(get_set_cookie_headers({}), [])


class TestCrawlCookies(unittest.TestCase):
    def test_crawl_collects_parsed_cookies(self):
        with Lab() as lab:
            out = crawl.run(lab_ctx(lab.url))
        self.assertEqual(len(out["data"]["cookies"]), 1)
        rec = out["data"]["cookies"][0]
        self.assertEqual(rec["name"], "lab_session")
        self.assertEqual(rec["page"], lab.url)
        self.assertNotIn("abc123", json.dumps(out))


class TestCookiesEngine(unittest.TestCase):
    def test_lab_cookie_flags(self):
        with Lab() as lab:
            ctx = lab_ctx(lab.url)
            ctx["crawl_cookies"] = crawl.run(ctx)["data"]["cookies"]
            out = cookies.run(ctx)
        names = [f["name"] for f in out["findings"]]
        self.assertIn("Cookie 'lab_session' has no HttpOnly flag", names)
        self.assertIn("Cookie 'lab_session' has no SameSite attribute",
                      names)
        # The lab is plain HTTP, so no Secure finding applies.
        self.assertFalse(any("Secure" in n for n in names))
        self.assertEqual(out["data"]["total"], 1)
        self.assertNotIn("abc123", json.dumps(out))

    def test_https_and_third_party(self):
        ctx = {"url": "https://example.com/", "host": "example.com",
               "domain": "example.com", "authorized": False, "timeout": 5,
               "html": "", "headers": {},
               "cookie_headers": [
                   "sess=SECRETVALUE1; Path=/; Secure",
                   "track=SECRETVALUE2; Domain=.tracker.com; Path=/"],
               "status": 200, "ips": [], "pages": [], "scripts": [],
               "subdomains": [], "crawl_cookies": []}
        out = cookies.run(ctx)
        names = [f["name"] for f in out["findings"]]
        self.assertIn("Cookie 'sess' has no HttpOnly flag", names)
        self.assertIn("Cookie 'track' has no Secure flag", names)
        self.assertIn("Cookie 'track' is a third-party cookie", names)
        self.assertEqual(out["data"]["third_party"], 1)
        blob = json.dumps(out)
        self.assertNotIn("SECRETVALUE1", blob)
        self.assertNotIn("SECRETVALUE2", blob)

    def test_long_lived_cookie(self):
        ctx = {"url": "https://example.com/", "host": "example.com",
               "domain": "example.com", "authorized": False, "timeout": 5,
               "html": "", "headers": {},
               "cookie_headers": [
                   "perm=x; Path=/; Secure; HttpOnly; SameSite=Lax; "
                   "Max-Age=63072000"],
               "status": 200, "ips": [], "pages": [], "scripts": [],
               "subdomains": [], "crawl_cookies": []}
        out = cookies.run(ctx)
        self.assertTrue(any("long-lived" in f["name"]
                            for f in out["findings"]))

    def test_no_cookies_is_completed(self):
        ctx = {"url": "https://example.com/", "host": "example.com",
               "domain": "example.com", "authorized": False, "timeout": 5,
               "html": "", "headers": {}, "cookie_headers": [],
               "status": 200, "ips": [], "pages": [], "scripts": [],
               "subdomains": [], "crawl_cookies": []}
        out = cookies.run(ctx)
        self.assertEqual(out["status"], "completed")
        self.assertEqual(out["data"]["total"], 0)


class TestCookiesValidator(unittest.TestCase):
    def test_new_style_finding_verifies_on_lab(self):
        with Lab() as lab:
            ctx = lab_ctx(lab.url)
            ev = {"engine": "cookies",
                  "name": "Cookie 'lab_session' has no HttpOnly flag",
                  "severity": "medium",
                  "evidence": "cookie lab_session (page /)",
                  "fix": "fix"}
            out = validator_mod.validate_one(ev, ctx)
        self.assertEqual(out["status"], "verified")

    def test_old_style_finding_still_verifies(self):
        with Lab() as lab:
            ctx = lab_ctx(lab.url)
            ev = {"engine": "web",
                  "name": "Cookie without HttpOnly flag",
                  "severity": "medium",
                  "evidence": "cookie lab_session",
                  "fix": "fix"}
            out = validator_mod.validate_one(ev, ctx)
        self.assertEqual(out["status"], "verified")


class TestWhoisParser(unittest.TestCase):
    def test_registrar_record_parsed_no_contact_data(self):
        with mock.patch(
                "fox.engines.whois.socket.create_connection",
                return_value=FakeSocket(REGISTRAR_RECORD)):
            out = whois.run(_whois_ctx())
        self.assertEqual(out["status"], "completed")
        self.assertEqual(out["data"]["registrar"],
                         "Example Registrar, Inc.")
        self.assertEqual(out["data"]["registrant_org"], "Example Org")
        self.assertEqual(out["data"]["created"], "1995-08-14")
        self.assertEqual(out["data"]["expires"], "2027-08-13")
        self.assertGreater(out["data"]["days_left"], 100)
        self.assertEqual(out["data"]["nameservers"],
                         ["a.iana-servers.net", "b.iana-servers.net"])
        self.assertIn("clientDeleteProhibited", out["data"]["status"])
        blob = json.dumps(out)
        self.assertNotIn("hidden@example.com", blob)
        self.assertNotIn("abuse@example-registrar.com", blob)

    def test_referral_followed(self):
        calls = []

        def _connect(addr, timeout=None):
            calls.append(addr)
            if addr[0] == "whois.verisign-grs.com":
                return FakeSocket(THIN_RECORD)
            return FakeSocket(REGISTRAR_RECORD)

        with mock.patch("fox.engines.whois.socket.create_connection",
                        side_effect=_connect):
            out = whois.run(_whois_ctx())
        self.assertEqual(out["status"], "completed")
        self.assertEqual(calls[0], ("whois.verisign-grs.com", 43))
        self.assertEqual(calls[1], ("whois.registrar-example.com", 43))
        self.assertEqual(out["data"]["hops"], 2)
        self.assertEqual(out["data"]["whois_server"],
                         "whois.registrar-example.com")

    def test_unknown_tld_asks_iana_first(self):
        calls = []

        def _connect(addr, timeout=None):
            calls.append(addr)
            if addr[0] == "whois.iana.org":
                return FakeSocket(IANA_RECORD)
            return FakeSocket(REGISTRAR_RECORD)

        with mock.patch("fox.engines.whois.socket.create_connection",
                        side_effect=_connect):
            out = whois.run(_whois_ctx("example.abcxyz"))
        self.assertEqual(out["status"], "completed")
        self.assertEqual(calls[0], ("whois.iana.org", 43))
        self.assertEqual(calls[1], ("whois.nic.abcxyz", 43))

    def test_expiry_soon_and_expired(self):
        soon = (datetime.datetime.utcnow()
                + datetime.timedelta(days=10)).strftime("%Y-%m-%d")
        rec = REGISTRAR_RECORD.replace("2027-08-13", soon)
        with mock.patch(
                "fox.engines.whois.socket.create_connection",
                return_value=FakeSocket(rec)):
            out = whois.run(_whois_ctx())
        self.assertEqual(out["data"]["days_left"], 9)
        self.assertTrue(any("expires soon" in f["name"]
                            for f in out["findings"]))
        old = REGISTRAR_RECORD.replace("2027-08-13", "2020-01-01")
        with mock.patch(
                "fox.engines.whois.socket.create_connection",
                return_value=FakeSocket(old)):
            out = whois.run(_whois_ctx())
        self.assertTrue(any("EXPIRED" in f["name"]
                            for f in out["findings"]))

    def test_port43_unreachable_is_error_with_rdap_fallback(self):
        with mock.patch(
                "fox.engines.whois.socket.create_connection",
                side_effect=socket.gaierror("blocked")):
            out = whois.run(_whois_ctx())
        self.assertEqual(out["status"], "error")
        self.assertIn("RDAP", out["data"]["error"])
        self.assertIn("port 43", out["data"]["error"])

    def test_local_target_is_completed(self):
        ctx = _whois_ctx("127.0.0.1")
        out = whois.run(ctx)
        self.assertEqual(out["status"], "completed")
        self.assertIn("Local test target", out["data"]["note"])


if __name__ == "__main__":
    unittest.main()
