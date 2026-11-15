#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Network Intelligence engine — Nmap style.

Rate-limited TCP connect scan of well-known ports against the
already-resolved IP (no DNS lookup per port), public banner grab,
service identification, and a TLS probe on HTTPS ports.
Authorized targets only. No exploitation, no auth bypass.
"""
import concurrent.futures
import socket
import ssl

NAME = "network"
TITLE = "Network Intelligence (Nmap)"

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    465: "smtps", 587: "smtp", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 1723: "pptp", 2049: "nfs",
    2082: "cpanel", 2083: "cpanel-ssl", 2086: "whm", 2087: "whm-ssl",
    2181: "zookeeper", 2222: "ssh-alt", 2375: "docker", 2376: "docker-ssl",
    3000: "node", 3306: "mysql", 3389: "rdp", 3690: "svn",
    4369: "epmd", 5000: "flask", 5432: "postgres", 5601: "kibana",
    5672: "rabbitmq", 5900: "vnc", 5984: "couchdb", 6000: "x11",
    6379: "redis", 7001: "cassandra", 8000: "http-alt", 8008: "http-alt",
    8080: "http-proxy", 8081: "http-alt", 8443: "https-alt",
    8888: "http-alt", 9000: "php-fpm", 9090: "http-alt", 9092: "kafka",
    9200: "elasticsearch", 9300: "elasticsearch", 9418: "git",
    10000: "webmin", 11211: "memcached", 15672: "rabbitmq-mgmt",
    27017: "mongodb", 27018: "mongodb", 28017: "mongodb-web",
}

RELATED = {8080: [8000, 8008, 8081, 8888, 8443, 9000, 9090],
           80: [8080, 8000, 8888], 443: [8443, 9443],
           3306: [33060], 5432: [5433], 6379: [6380],
           27017: [27018, 28017], 22: [2222]}


def _grab(sock):
    try:
        sock.settimeout(0.6)
        return sock.recv(256).decode(errors="ignore").strip()[:120]
    except Exception:
        return ""


def _check(ip, port, timeout=0.4):
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except Exception:
        return None
    banner = _grab(sock)
    tls_info = None
    if port in (443, 8443, 9443, 2083, 2087, 465, 993, 995):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            wrapped = ctx.wrap_socket(sock, server_hostname=ip)
            cert = wrapped.getpeercert(binary_form=False) or {}
            tls_info = {"version": wrapped.version(),
                        "cipher": (wrapped.cipher() or [None])[0],
                        "issuer": str(cert.get("issuer", ""))[:120]}
            wrapped.close()
            return {"port": port, "service": COMMON_PORTS.get(port, "?"),
                    "state": "open", "banner": banner, "tls": tls_info}
        except Exception:
            pass
    try:
        sock.close()
    except Exception:
        pass
    return {"port": port, "service": COMMON_PORTS.get(port, "?"),
            "state": "open", "banner": banner, "tls": tls_info}


def _scan(ip, ports, timeout=0.4, workers=30):
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(_check, ip, p, timeout): p for p in ports}
        for fut in futs:
            try:
                res = fut.result()
            except Exception:
                res = None
            if res:
                found.append(res)
    return sorted(found, key=lambda r: r["port"])


def run(ctx):
    if not ctx.get("authorized"):
        return {"engine": NAME, "status": "not_tested",
                "findings": [], "data": {"note": "needs authorization"}}
    ips = ctx.get("ips") or []
    if not ips:
        return {"engine": NAME, "status": "error",
                "findings": [], "data": {"error": "no IP resolved"}}
    ip = ips[0]
    timeout = ctx.get("timeout", 8)
    phase1 = _scan(ip, sorted(COMMON_PORTS), timeout=0.4)
    tried = set(COMMON_PORTS)
    related = []
    for item in phase1:
        for p in RELATED.get(item["port"], []):
            if p not in tried:
                related.append(p)
                tried.add(p)
    phase2 = _scan(ip, related, timeout=0.4) if related else []
    open_ports = sorted(phase1 + phase2, key=lambda r: r["port"])
    findings = []
    risky = {21, 23, 3306, 5432, 6379, 27017, 5900, 1433, 3389, 445, 2375}
    for item in open_ports:
        if item["port"] in risky:
            findings.append({
                "severity": "high",
                "name": "Sensitive service exposed: %s on port %d"
                        % (item["service"], item["port"]),
                "evidence": "port %d open, banner: %s"
                            % (item["port"], item.get("banner") or "—"),
                "fix": "Close port %d to the internet or restrict it "
                       "to trusted networks only." % item["port"]})
        elif item["port"] in (23, 21):
            findings.append({
                "severity": "medium",
                "name": "Insecure legacy service on port %d" % item["port"],
                "evidence": "port %d open" % item["port"],
                "fix": "Disable Telnet/FTP; use SSH/SFTP instead."})
    return {"engine": NAME, "status": "completed", "findings": findings,
            "data": {"ip": ip, "open_ports": open_ports,
                     "open_count": len(open_ports),
                     "phase1": len(COMMON_PORTS),
                     "phase2_related": len(related)}}
