#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Engine registry: every engine in the FOX, in run order."""
from . import cookies, crawl, dns, fuzz, history, httpx, network, owner
from . import resources, secrets, semgrep, shodan, subdomains, tech
from . import tls, vuln, web, whois, wordpress

ENGINES = [web, crawl, tls, tech, vuln, subdomains, history, httpx,
           wordpress, semgrep, secrets, network, fuzz, shodan,
           owner, resources, dns, cookies, whois]

BY_NAME = {e.NAME: e for e in ENGINES}

# Profiles: which engines run.
PROFILES = {
    "quick": ["web", "crawl", "tls", "tech"],
    "deep": ["web", "crawl", "tls", "tech", "vuln", "subdomains",
             "httpx", "wordpress", "semgrep", "secrets", "network", "fuzz",
             "owner", "resources", "dns", "cookies", "whois"],
    "forensic": ["web", "crawl", "tls", "tech", "vuln", "subdomains",
                 "history", "httpx", "wordpress", "semgrep", "secrets",
                 "network", "fuzz", "shodan", "owner", "resources",
                 "dns", "cookies", "whois"],
}
