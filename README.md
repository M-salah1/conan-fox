# 🦊 CONAN FOX NOVA v2.30 — ULTIMATE SECURITY INVESTIGATION SYSTEM

**Developer:** Hafed Mehdi Salah Eddine — Algeria
**Organization:** FOX COMPANY
**Platform:** Python 3 (standard library only) — Termux / Linux / Windows
**Interface:** Terminal console in Arabic / English / French

One tool, seventeen engines. Each engine does the job of a famous
professional tool — re-implemented in Python for Termux, defensive
only, no exploitation, no login bypass, no secret values ever shown.

## The engines

| Engine | Does the job of | What it really does |
| ------ | --------------- | ------------------- |
| `web` | OWASP ZAP | Security headers, forms, HTTPS enforcement, mixed content |
| `cookies` | Cookies inventory | Every Set-Cookie from the homepage + all crawled pages: name, flags (Secure/HttpOnly/SameSite), lifetime, first/third-party — values never kept |
| `whois` | WHOIS (port 43) | Raw registration record via TCP port 43 with referral chain: registrar, registrant org, creation/expiry dates, nameservers, status; RDAP owner engine stays the fallback |
| `vuln` | Nuclei / Nikto | 16 read-only templates: exposed .git, .env, backups, configs, phpinfo, server-status, API docs |
| `network` | Nmap | Rate-limited TCP connect scan (common ports + related neighbours), banner grab, TLS probe |
| `subdomains` | Subfinder / Amass | Certificate Transparency (crt.sh) + DNS wordlist via DoH + wildcard check |
| `httpx` | httpx | Live probe of every discovered host: status, title, server, TLS |
| `crawl` | Katana | Same-host crawl: pages, links, forms, scripts, stylesheets, e-mails, cookies set on each page |
| `fuzz` | FFUF | 60-path parallel wordlist probe (authorized targets only) |
| `tls` | testssl.sh / SSLyze | TLS 1.0–1.3 negotiation, cipher, certificate (issuer/SANs/expiry), HSTS |
| `tech` | WhatWeb | Server, X-Powered-By, generator, CMS, JS library versions |
| `history` | GAU | Wayback Machine CDX API: archived URLs, first/last seen |
| `secrets` | Gitleaks | Secret patterns in public text — names + locations only, values redacted |
| `wordpress` | WPScan | WP detection, public version, themes/plugins, REST API (detection only) |
| `semgrep` | Semgrep | Static patterns in public JS: eval, innerHTML, hardcoded credentials |
| `shodan` | Shodan | Host intel — only with your own `SHODAN_API_KEY` env var, else `not_configured` |
| `owner` | Owner Intelligence | Public RDAP: registrar, registrant org + handle (ID), registration/expiry dates, nameservers; certificate days left |
| `resources` | Resource Inventory | Every public asset (JS/CSS/images/fonts): status, size, internal/external, broken links |
| `dns` | DNS Intelligence | A/AAAA/MX/NS/TXT/CNAME/SOA/CAA/DS via DoH, SPF, DMARC, DNSSEC |

## Framework Core (v2.20) — the brain

Engines no longer report straight to the score. Every finding flows
through a central pipeline:

```
engines -> Evidence Collector -> Validation Engine -> Correlation Engine
        -> Scoring -> Final Intelligence Report (+ Asset Intelligence)
```

- **Evidence Collector** (`core/evidence.py`) — every finding becomes
  one evidence record: engine, time, what was seen. One ID per record.
- **Validation Engine** (`core/validator.py`) — every finding is
  re-checked independently of the engine that found it: missing
  headers re-fetched, cookies re-checked, exposed paths re-GET,
  secret/JS patterns re-matched, TLS re-handshaken. Result: verified /
  observed / false_positive + confidence. False positives are removed
  from the score and listed separately — never silently counted.
- **Correlation Engine** (`core/correlation.py`) — merges duplicate
  findings across engines (one finding per problem) and detects
  attack chains no single engine can see (XSS session theft,
  session hijack on the wire, source + secrets exposure), plus
  contradictions between engines.
- **Scoring** (`core/scoring.py`) — one place where a score comes
  from; only validated findings count, and every finding explains
  WHY it is HIGH (evidence + validation + chain).
- **Asset Intelligence** (`core/assets.py`) — one linked inventory:
  domain, subdomains, IPs, ports, certificates, technologies,
  cookies, pages — and the links between them.

Console (per-engine menu and comparison):

```
fox > engines                 # list all 17 engines
fox > engine web https://example.com   # run one engine alone
fox > compare 1 2             # diff two previous investigations
```

Still Python stdlib only — no pip installs in Termux. External tools
(ZAP, Nmap, testssl.sh) stay optional integrations for authorized
audits, never dependencies.

Next steps on the roadmap: API Intelligence, Code/Dependency
Intelligence, Digital Forensics timeline, professional dashboard.

## Intelligent Verification (v2.20) — four honest metrics

The aadl.dz v2.00 report showed the problem: a bare HTTP 200 was
treated as a confirmed leak, 61 open TCP ports as 61 confirmed
services, a 403 as a finding, and 15 unconfirmed "High" findings
produced a misleading 0%.

- **Content-aware verification** (`core/content.py`) — the error
  page is fingerprinted first (two random paths); a 200 whose body
  matches it is an error page, not a file. Sensitive files must
  structurally match what they claim (.env needs KEY= lines, .sql
  needs SQL keywords, .git/HEAD must start with "ref:"). Only key
  NAMES are ever reported.
- **Status classification** — 200 real content / redirect /
  auth required / forbidden (not a finding) / absent / rate
  limited / server error. 403 is never a vulnerability.
- **Network service states** — tcp_open → service_identified →
  service_confirmed (banner match / HTTP response / TLS handshake).
  An empty banner is usually a firewall answering SYNs, not a
  service. No authentication is ever attempted.
- **Four separate metrics** — Security Score (confirmed findings
  only; indicators weigh half; false positives and info weigh
  nothing), Confidence (computed from validation, never fixed),
  Coverage (measured: engines + crawl visited/discovered +
  subdomains probed/found + ports), Verification Rate (share of
  findings verified).
- **Resume** — `resume <id>` re-runs only the timed-out / failed
  engines of a stored scan and updates it.
- **Errors are errors** — a CT 404 or RDAP 404 means "unknown, not
  absent"; subdomains/owner report the error instead of claiming
  nothing exists.
- **Semgrep** analyses only the site's own scripts; third-party
  libraries are reported separately as info. **Secrets** now checks
  the homepage + 10 scripts + 5 crawled pages. **Crawl** reports
  discovered vs visited pages.

## Cookies + WHOIS (v2.30)

- **Cookies engine** (`engines/cookies.py`) — the homepage is not
  the only place that sets cookies. The crawler now captures the
  Set-Cookie header of every page it visits (parsed immediately
  into a value-free record: name + flags only), and the cookies
  engine inventories all of them: Secure / HttpOnly / SameSite,
  session vs persistent, lifetime (long-lived > 1 year is flagged),
  first-party vs third-party. Cookie-flag findings moved here from
  the web engine, named per cookie ("Cookie 'sess' has no HttpOnly
  flag"), and the validator re-checks the exact page the cookie
  came from. Cookie VALUES are never collected, shown or stored —
  a value is a session secret; to check a value you own, use
  Verify (dashboard option 4): type it hidden, get YES/NO +
  location only.
- **WHOIS engine** (`engines/whois.py`) — a real RFC 3912 client:
  TCP port 43, a TLD server map (com/net/org/io/dz/fr/de/uk and
  more, IANA lookup for the rest), and referral following to the
  registrar's server (max 3 hops). Parsed fields only: registrar,
  registrant organization (when published), creation / expiry /
  update dates with days left, nameservers, status. The raw record
  is never kept or shown (it can contain personal contact data);
  registrant e-mail, phone and address are never collected, and a
  redacted record is reported as redacted. When port 43 is
  unreachable from the machine running the scan, the engine
  reports an error and the RDAP-based owner engine stays the
  fallback — the scan still completes.

## What NOVA adds (v2.00)

- **Welcome screen** — on entry: tool introduction, the 16 engines,
  developer credit, how-to. `about` shows it again any time.
- **Owner Intelligence** — the site owner's public identity and ID
  (registrar + registrant handle from RDAP), domain expiry in days,
  certificate expiry in days. Redacted data is reported UNKNOWN.
- **Cookies, fully detailed** — every cookie by name with Secure /
  HttpOnly / SameSite / domain / path / expiry / session flags.
  Values are never collected or shown.
- **Hidden fields & password fields** — hidden `<input>` names,
  password-field count, HTML-comment pattern scan. Names only;
  values are never collected or shown.
- **Resource inventory** — all public assets with status and size.
- **Verification Mode** — after a scan, dashboard option **4. Verify**:
  type an owner-provided value hidden; FOX checks in memory whether
  it appears in any public place the scan found and answers YES/NO +
  location only. The value never appears in any result or report.
  Real passwords and session values are never displayed by FOX —
  a displayed secret is a leaked secret.

## What is NOT inside, and why

- **Burp Suite** — a commercial Java proxy with manual interception.
  FOX's `web` engine does its automated part (request/response
  analysis); interactive proxying needs Burp itself.
- **Metasploit / sqlmap** — exploitation frameworks. FOX is defensive
  only: it finds and reports holes, it never exploits them.
- **Wireshark** — packet capture needs root and pcap; not possible
  from a Termux Python tool. FOX's `network` engine covers the
  reachable equivalent (connect scan + banners).
- **Shodan / Censys data** — commercial APIs. FOX queries Shodan only
  when you set your own key; it never invents Shodan data.

## Profiles

- `quick` — web + crawl + tls + tech (fast, passive).
- `deep` — all engines except history/shodan; network + fuzz need authorization.
- `forensic` — everything, including history + Shodan (if configured).

## Honest scoring

- Score = 100 − severity weights (critical 25, high 15, medium 8, low 3).
- Coverage = engines completed / engines planned.
- Coverage below 50%, or an unreachable target, gives **INCOMPLETE** —
  never a misleading 0%.

## Install (Termux)

```bash
pkg update && pkg install -y python git
git clone <repo-url>
cd conan-fox
python3 fox.py
```

No dependencies to install — Python standard library only.

## Run

```bash
python3 fox.py                                  # console
python3 fox.py https://example.com              # direct scan (deep)
python3 fox.py https://example.com --profile quick --json fox-report.json
python3 fox.py https://example.com --profile forensic --html fox-report.html
```

Console commands: `scan <url>`, `profile <quick|deep|forensic>`,
`history`, `lang`, `help`, `exit`. The first scan asks for the
ethical terms (type `y`); active checks ask once for authorization
(your own site or written permission).

Optional: `SHODAN_API_KEY=... python3 fox.py <url>` enables the
Shodan engine. The key is read from the environment only — it is
never stored in a file or shown in any report.

## Storage

- `fox-scans.db` — SQLite: one row per scan + one row per engine run.
- `fox-scope.json` — remembered authorizations.
- `fox-settings.json` — language + profile.
- `fox-report.json` / `fox-report.html` — exports.

## Tests

```bash
python3 -m unittest tests.test_fox tests.test_framework tests.test_verify2 tests.test_cookies_whois -v
```

77 tests, all passing (2026-11-15): every engine against a local lab
(41 in test_fox, 20 framework/verification in test_verify2, 16
cookies + WHOIS in test_cookies_whois — the WHOIS tests use mocked
sockets, since port 43 is blocked in the sandbox; on Termux it
queries the real WHOIS servers)
server, orchestrator quick/deep, INCOMPLETE on a dead target, SQLite
round-trip. Smoke: example.com deep scan in ~19s, 10/12 engines
completed (network + fuzz correctly `not_tested` without
authorization), score 60% D, coverage 83%.
