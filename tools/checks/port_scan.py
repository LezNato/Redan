#!/usr/bin/env python
"""port_scan.py — web-focused service discovery (deterministic, dependency-free).

Purpose for WEB engagements: discover the full web attack surface of an in-scope
host — every HTTP/HTTPS service across standard, app, dev, and management ports
(e.g. staging on :8080, an admin panel on :8443, a dev API on :3000) — and surface
any exposed non-web service (DB/cache/mgmt) as a finding. The discovered web
endpoints feed the web-tester so it tests more than just :443.

Method: threaded TCP-connect scan (no raw sockets / privileges / nmap needed),
then a lightweight HTTP(S) probe + banner grab on open ports. Non-destructive
(connect + minimal read), rate-limited via a concurrency cap. IPv4. ACTIVE —
in-scope hosts only; the calling agent enforces scope.

Usage:
  python port_scan.py <host> [--profile web|web-mgmt|common] [--ports 80,443,8080]
                              [--timeout 2.0] [--concurrency 40]
"""
import sys, os, json, ssl, socket, argparse, re, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _concurrency import workers

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

WEB = [80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8090, 8888, 3000, 3001, 4200,
       5000, 5173, 9000, 9443, 4443, 7001, 7002]
MGMT = [2082, 2083, 2086, 2087, 2095, 2096, 8083, 10000]          # cPanel/Plesk/Webmin
SERVICES = [21, 22, 23, 25, 110, 143, 1433, 3306, 5432, 5900, 6379, 9200, 11211, 27017]
PROFILES = {"web": WEB, "web-mgmt": WEB + MGMT, "common": WEB + MGMT + SERVICES}

TLS_HINT = {443, 8443, 9443, 4443, 2083, 2087, 2096, 8083}        # try HTTPS first
PORT_SERVICE = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 110: "pop3", 143: "imap",
                1433: "mssql", 3306: "mysql", 5432: "postgres", 5900: "vnc", 6379: "redis",
                9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
                2082: "cpanel", 2083: "cpanel-ssl", 2086: "whm", 2087: "whm-ssl",
                2095: "webmail", 2096: "webmail-ssl", 10000: "webmin"}
SENSITIVE = {"mysql", "postgres", "mssql", "redis", "elasticsearch", "memcached",
             "mongodb", "vnc", "telnet", "ftp"}
MGMT_SVC = {"cpanel", "cpanel-ssl", "whm", "whm-ssl", "webmail", "webmail-ssl", "webmin"}

def connect(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def http_probe(host, port, timeout):
    schemes = ["https", "http"] if port in TLS_HINT else ["http", "https"]
    for scheme in schemes:
        url = f"{scheme}://{host}:{port}/"
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            r = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            body = r.read(4096).decode("utf-8", "replace")
            code, hdrs = r.getcode(), r.headers
        except urllib.error.HTTPError as e:
            body, code, hdrs = "", e.code, e.headers
        except Exception:
            continue
        t = re.search(r"<title[^>]*>([^<]{0,120})", body, re.I)
        return {"scheme": scheme, "status": code, "server": hdrs.get("Server"),
                "x_powered_by": hdrs.get("X-Powered-By"),
                "title": t.group(1).strip() if t else None, "url": url}
    return None

def grab_banner(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(160)
        b = data.decode("latin-1", "replace").strip()
        return re.sub(r"\s+", " ", b)[:160] or None
    except Exception:
        return None

def identify(host, port, timeout):
    web = http_probe(host, port, timeout)
    if web:
        return {"port": port, "service": "https" if web["scheme"] == "https" else "http",
                **{k: web[k] for k in ("scheme", "status", "server", "x_powered_by", "title", "url")}}
    banner = grab_banner(host, port, timeout)
    return {"port": port, "service": PORT_SERVICE.get(port, "unknown"), "banner": banner}

def scan(host, ports, timeout, concurrency):
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"target": host, "ok": False, "error": f"resolve failed: {e}"}
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        openp = sorted(p for p, ok in zip(ports, ex.map(lambda p: connect(host, p, timeout), ports)) if ok)
    details = [identify(host, p, timeout) for p in openp]
    web_surfaces = [d["url"] for d in details if d.get("url")]
    findings = []
    for d in details:
        svc = d["service"]
        if svc in SENSITIVE:
            findings.append({"id": "exposed-service", "severity": "high",
                             "detail": f"{svc} reachable on {host}:{d['port']} — should not be internet-exposed"})
        elif svc in MGMT_SVC:
            findings.append({"id": "exposed-mgmt-panel", "severity": "medium",
                             "detail": f"{svc} management panel on {host}:{d['port']}"})
    extra_web = [d for d in details if d.get("url") and d["port"] not in (80, 443)]
    if extra_web:
        findings.append({"id": "additional-web-surface", "severity": "info",
                         "detail": "non-standard web service(s): " + ", ".join(d["url"] for d in extra_web)
                                   + " — test these too"})
    return {"target": host, "ip": ip, "ok": True, "scanned": len(ports),
            "open": details, "web_surfaces": web_surfaces, "findings": findings}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="web-focused service discovery (TCP connect)")
    ap.add_argument("host")
    ap.add_argument("--profile", choices=list(PROFILES), default="web")
    ap.add_argument("--ports", help="comma-separated override, e.g. 80,443,8080")
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--concurrency", type=int, default=None, help="default: core-scaled (cores*4, cap 100)")
    a = ap.parse_args()
    ports = [int(p) for p in a.ports.split(",")] if a.ports else PROFILES[a.profile]
    print(json.dumps(scan(a.host, ports, a.timeout, workers(cap=100, want=a.concurrency)), indent=2))
