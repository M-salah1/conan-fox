#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Engine registry: every engine in the FOX, in run order."""
from . import crawl, dns, fuzz, history, httpx, network, owner, resources
from . import secrets, semgrep, shodan, subdomains, tech, tls, vuln
from . import web, wordpress

ENGINES = [web, crawl, tls, tech, vuln, subdomains, history, httpx,
           wordpress, semgrep, secrets, network, fuzz, shodan,
           owner, resources, dns]

BY_NAME = {e.NAME: e for e in ENGINES}

# Profiles: which engines run.
PROFILES = {
    "quick": ["web", "crawl", "tls", "tech"],
    "deep": ["web", "crawl", "tls", "tech", "vuln", "subdomains",
             "httpx", "wordpress", "semgrep", "secrets", "network", "fuzz",
             "owner", "resources", "dns"],
    "forensic": ["web", "crawl", "tls", "tech", "vuln", "subdomains",
                 "history", "httpx", "wordpress", "semgrep", "secrets",
                 "network", "fuzz", "shodan", "owner", "resources", "dns"],
}
