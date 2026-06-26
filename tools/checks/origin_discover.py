#!/usr/bin/env python
"""origin_discover.py — find a CDN/WAF-fronted site's real ORIGIN (WAF-bypass recon).

A WAF/CDN only protects if ALL traffic is forced through it. If the origin server
still accepts direct connections (firewall not locked to the CDN's IP ranges), an
attacker discovers the origin IP and connects straight to it — skipping the WAF
entirely. That exposure is itself a finding.

Vectors (passive-ish + a few direct probes; non-destructive):
  - cert transparency (crt.sh, free) + common non-proxied subdomains → candidate IPs
  - classify each IP as known-CDN (Cloudflare) vs likely-origin
  - probe each likely-origin IP directly (TLS SNI + Host: <domain>) and compare to the
    edge fingerprint — if it serves the site's real content past the challenge, the WAF
    is bypassable.

Authorized targets only. Usage:  python origin_discover.py <domain>
"""
import sys, os, re, ssl, json, socket, ipaddress, argparse, urllib.request
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _concurrency import workers

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
CF_RANGES = ["173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","141.101.64.0/18",
             "108.162.192.0/18","190.93.240.0/20","188.114.96.0/20","197.234.240.0/22","198.41.128.0/17",
             "162.158.0.0/15","104.16.0.0/13","104.24.0.0/14","172.64.0.0/13","131.0.72.0/22"]
CF_NETS = [ipaddress.ip_network(c) for c in CF_RANGES]
SUBS = ["", "www", "mail", "webmail", "cpanel", "ftp", "direct", "origin", "dev", "staging",
        "server", "host", "ns1", "ns2", "smtp", "mx", "autodiscover", "vpn", "remote", "portal",
        "test", "old", "api", "cdn", "email", "secure", "shop", "blog"]

def cdn(ip):
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in CF_NETS)
    except Exception:
        return False

def resolve(name):
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(name, 443, socket.AF_INET)})
    except Exception:
        return []

def crtsh(domain):
    try:
        r = urllib.request.urlopen(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30)
        names = set()
        for row in json.load(r):
            for n in str(row.get("name_value", "")).split("\n"):
                n = n.strip().lstrip("*.").lower()
                if n.endswith(domain):
                    names.add(n)
        return sorted(names)
    except Exception:
        return []

def fetch_raw(ip, domain, timeout=10):
    """Direct HTTPS to ip with SNI+Host=domain; return (status, server_header, snippet)."""
    try:
        sock = socket.create_connection((ip, 443), timeout=timeout)
    except Exception as e:
        return None, None, f"connect: {e}"
    try:
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(sock, server_hostname=domain)
        s.sendall(f"GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: {UA}\r\nConnection: close\r\n\r\n".encode())
        s.settimeout(timeout)
        data = b""
        while len(data) < 8000:
            ch = s.recv(2048)
            if not ch: break
            data += ch
        text = data.decode("latin-1", "replace")
        status = int(re.match(r"HTTP/\d\.\d (\d+)", text).group(1)) if re.match(r"HTTP/\d\.\d (\d+)", text) else None
        server = (re.search(r"(?im)^Server:\s*(.+)$", text) or [None, ""])[1].strip()
        body = text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in text else ""
        return status, server, body[:300].replace("\n", " ")
    except Exception as e:
        return None, None, f"tls/http: {e}"
    finally:
        try: s.close()
        except Exception:
            try: sock.close()
            except Exception: pass

def discover(domain):
    # 1) edge fingerprint (what normal traffic gets)
    edge_ips = resolve(domain)
    edge_status, edge_server, edge_snip = (fetch_raw(edge_ips[0], domain) if edge_ips else (None, None, ""))
    # 2) gather candidate names: common subs + crt.sh
    names = {(s + "." + domain if s else domain) for s in SUBS} | set(crtsh(domain))
    # 3) resolve all
    with ThreadPoolExecutor(max_workers=workers(cap=24)) as ex:
        resolved = list(ex.map(lambda nm: (nm, resolve(nm)), sorted(names)))
    ip_map = {}
    for nm, ips in resolved:
        for ip in ips:
            ip_map.setdefault(ip, []).append(nm)
    edge_set = set(edge_ips)
    candidates = {ip: nms for ip, nms in ip_map.items() if not cdn(ip) and ip not in edge_set}
    # 4) probe likely-origin candidates directly
    def probe(ip):
        st, srv, snip = fetch_raw(ip, domain)
        serves = bool(st and st < 500 and ("wordpress" in snip.lower() or "<html" in snip.lower()
                                           or (edge_server and srv and srv.split("/")[0] == edge_server.split("/")[0])))
        return {"ip": ip, "names": ip_map.get(ip, []), "status": st, "server": srv,
                "serves_site_directly": serves, "snippet": snip}
    with ThreadPoolExecutor(max_workers=workers(cap=8)) as ex:
        probes = list(ex.map(probe, list(candidates)[:25]))
    hits = [p for p in probes if p["serves_site_directly"]]
    findings = []
    for p in hits:
        findings.append({"id": "origin-exposed-bypassing-waf", "severity": "high", "cwe": "CWE-693",
                         "detail": f"origin {p['ip']} ({', '.join(p['names'][:3])}) serves {domain} directly "
                                   f"(Server: {p['server']}) — WAF/CDN bypassable by connecting to the origin IP"})
    return {"target": domain, "ok": True,
            "edge": {"ips": edge_ips, "behind_cloudflare": any(cdn(i) for i in edge_ips),
                     "status": edge_status, "server": edge_server},
            "subdomains_found": sorted(names), "candidate_origin_ips": list(candidates),
            "probes": probes, "origin_exposed": bool(hits), "findings": findings,
            "note": "an origin that serves the site directly = WAF bypass. Lock the origin firewall to the CDN ranges + rotate the IP."}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("domain")
    a = ap.parse_args()
    print(json.dumps(discover(a.domain), indent=2))
