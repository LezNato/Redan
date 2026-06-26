#!/usr/bin/env python
"""recon_sweep.py — run the whole deterministic check layer CONCURRENTLY.

Instead of the recon agent calling 8 tools one after another, this fans them out
across threads — http_headers + path_probe + port_scan + wp_fingerprint (+ tls_check
when HTTPS; dns_email + host_intel + wayback_recon when a named, non-local host) —
and returns one combined JSON. Wall-clock becomes ~the slowest single check, not the
sum. Core-scaled (each sub-check threads internally too). The agents/verifier consume
the same per-check JSON they already trust; `findings` is a flat merged list.

Usage: python recon_sweep.py <url-or-host>
"""
import sys, os, json, socket, argparse
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import http_headers, tls_check, dns_email, wp_fingerprint, path_probe, port_scan, host_intel, wayback_recon
from _concurrency import workers

def sweep(target):
    if "://" not in target:
        target = "http://" + target
    u = urlparse(target)
    host = u.hostname or target
    scheme = u.scheme or "http"
    port = u.port or (443 if scheme == "https" else 80)
    base = f"{scheme}://{u.netloc}"
    is_ip = host.replace(".", "").isdigit() or ":" in host
    is_local = host in ("localhost", "127.0.0.1", "::1")

    tasks = {}
    with ThreadPoolExecutor(max_workers=8) as ex:
        tasks["headers"] = ex.submit(http_headers.check, base + "/")
        tasks["paths"] = ex.submit(path_probe.check, base)
        tasks["ports"] = ex.submit(port_scan.scan, host, port_scan.PROFILES["web"], 2.0, workers(cap=100))
        tasks["wordpress"] = ex.submit(lambda: wp_fingerprint.fingerprint(wp_fingerprint.fetch(base + "/"), base))
        if scheme == "https":
            tasks["tls"] = ex.submit(tls_check.check, f"{host}:{port}")
        if not (is_ip or is_local):
            tasks["dns_email"] = ex.submit(dns_email.check, host)
            # passive recon multipliers (hit archive.org / Shodan, NOT the target):
            tasks["wayback"] = ex.submit(wayback_recon.sweep, host, None, None, 200)
            try:
                _ip = socket.gethostbyname(host)
                tasks["host_intel"] = ex.submit(host_intel.lookup, _ip)
            except Exception:
                pass
        results = {}
        for k, f in tasks.items():
            try:
                results[k] = f.result()
            except Exception as e:
                results[k] = {"ok": False, "error": str(e)}

    merged = []
    for k, r in results.items():
        for fnd in (r.get("findings") or []):
            merged.append({"check": k, **fnd})
    return {"ok": True, "target": target, "host": host, "checks": results,
            "findings_merged": merged, "finding_count": len(merged)}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Run the whole deterministic recon check layer concurrently.")
    ap.add_argument("target", metavar="url-or-host", help="target URL or bare hostname")
    args = ap.parse_args()
    print(json.dumps(sweep(args.target), indent=2))
