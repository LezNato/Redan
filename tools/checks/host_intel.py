#!/usr/bin/env python
"""host_intel.py — passive host-IP enrichment via Shodan InternetDB (stdlib only, no API key).

Reads Shodan's ALREADY-COLLECTED scan data for an IP (https://internetdb.shodan.io/<ip>).
NO scan of our own — respects the shared-host / no-active-scan RoE (the IP may host other
tenants). Emits CPEs, ports, hostnames, tags, and a vulns[] list tagged as LEADS.

Pairs with origin_discover.py: that FINDS an origin IP; this ENRICHES it (ports / product-CPE
versions / known-vuln hints). A single passive GET can upgrade a banner-guessed
component CVE from version-lead to version-confirmed.

Usage: python host_intel.py <ip-or-host> [<ip-or-host> ...] [--timeout 15]
"""
import sys, json, socket, urllib.request, urllib.error, argparse

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
INTERNETDB = "https://internetdb.shodan.io/"

def resolve(target):
    try:
        socket.inet_aton(target)
        return target  # already an IPv4
    except OSError:
        pass
    try:
        return socket.gethostbyname(target)
    except Exception:
        return None

def lookup(ip, timeout=15):
    req = urllib.request.Request(INTERNETDB + ip, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            d = json.load(r)
    except urllib.error.HTTPError as e:
        return {"target": ip, "ok": False, "error": f"HTTP {e.code} (Shodan has no indexed data, or blocked)", "findings": []}
    except Exception as e:
        return {"target": ip, "ok": False, "error": str(e), "findings": []}
    cpes = d.get("cpes", [])
    findings = []
    notable = [c for c in cpes if any(k in c.lower() for k in ("openresty", "nginx", "apache", "php:", "iis", "haproxy", " envoy"))]
    if notable:
        findings.append({"id": "versioned-edge-product", "severity": "info",
                         "detail": "versioned edge/server product(s) on the host — cross-check against version-bound CVEs: " + "; ".join(notable[:6])})
    if d.get("tags"):
        findings.append({"id": "host-tags", "severity": "info", "detail": "Shodan tags: " + ", ".join(d["tags"])})
    if d.get("vulns"):
        findings.append({"id": "shodan-vulns", "severity": "medium",
                         "detail": f"Shodan lists {len(d['vulns'])} CVEs for this IP — LEAD: on a SHARED host these may belong to a CO-TENANT, not this target; attribute carefully and verify the CVE on-target",
                         "cves": d["vulns"][:20]})
    co_hosts = [h for h in d.get("hostnames", []) if h]
    if co_hosts:
        findings.append({"id": "shared-host-evidence", "severity": "info",
                         "detail": f"hostnames on this IP: {', '.join(co_hosts[:8])} — if any are NOT the target's, the IP is shared (port-scanning it would hit other tenants = out of scope)"})
    return {"target": ip, "ok": True, "ip": ip, "hostnames": co_hosts,
            "cpes": cpes, "ports": d.get("ports", []), "tags": d.get("tags", []),
            "vulns": d.get("vulns", []), "findings": findings,
            "note": "PASSIVE (reads Shodan's collected data; no scan). vulns[] are HOST-LEVEL LEADS — on shared hosting they may be co-tenant; the verifier must demonstrate the CVE on THIS target (pitfalls.md: version-banner != vuln)."}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Passive Shodan InternetDB host-IP enrichment")
    ap.add_argument("targets", nargs="+", help="IP or hostname(s)")
    ap.add_argument("--timeout", type=int, default=15)
    a = ap.parse_args()
    out = []
    for t in a.targets:
        ip = resolve(t)
        if not ip:
            out.append({"target": t, "ok": False, "error": "unresolved", "findings": []}); continue
        out.append(lookup(ip, a.timeout))
    print(json.dumps(out if len(out) > 1 else out[0], indent=2))
