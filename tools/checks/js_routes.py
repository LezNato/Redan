#!/usr/bin/env python
"""js_routes.py — deep JS-endpoint extraction (stdlib only).

The crawler's JS-endpoint regex is a fixed allowlist prefix, so most app-specific deep/unlinked
endpoints (where attackers find the weird internal/deprecated route — found by luck,
not a systematic JS sweep) are dropped. This tool fetches the page + all same-origin JS chunks and
extracts the FULL callable set: fetch/axios/XHR string-literal URLs, SPA route tables
(path:'/...', <Route path=, routes: [{path...}]), and embedded GraphQL operation names. Emits
every candidate (incl. unlinked/internal) for direct probing, post-filtered against static-asset noise.

Usage: python js_routes.py <url> [--max-js N]
"""
import os, sys, json, re, argparse
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _http import get as http_get

# callable-endpoint patterns
FETCH_RE = re.compile(r"""(?:fetch|axios(?:\.(?:get|post|put|delete|patch))?|\\\$\.ajax|\.(?:get|post|put|delete|patch)\s*\(|XMLHttpRequest)[^"']{0,40}["']([~/][^"']{2,120})["']""", re.I)
STRING_PATH_RE = re.compile(r"""["']((?:/|\\/)(?:api|rest|v\d|graphql|gql|admin|user|account|auth|login|logout|register|upload|export|import|search|graphql|internal|private|debug|test|dev|staging)[^"']{0,100})["']""", re.I)
ROUTE_TABLE_RE = re.compile(r"""(?:path|route)\s*:\s*["']([/~/][^"']{1,120})["']""", re.I)
GQL_OP_RE = re.compile(r"""(?:query|mutation)\s+([A-Za-z0-9_]+)\s*[({]""")
STATIC_NOISE = re.compile(r"\.(?:png|jpg|jpeg|gif|svg|ico|css|woff2?|ttf|map|webp|mp4|webm)(?:\?|$)", re.I)

def fetch(url, timeout=15):
    r = http_get(url, timeout=timeout, max_body=5_000_000)
    return "" if (r.error or r.status >= 400) else r.text

def extract(blob):
    routes = set()
    for rx in (FETCH_RE, STRING_PATH_RE, ROUTE_TABLE_RE):
        for m in rx.findall(blob):
            p = m.replace("\\/", "/")
            if not STATIC_NOISE.search(p):
                routes.add(p)
    gql = set(GQL_OP_RE.findall(blob))
    return routes, gql

def sweep(url, max_js=25):
    host = urlparse(url).netloc
    html = fetch(url)
    js_urls = []
    for m in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
        full = urljoin(url, m)
        if urlparse(full).netloc == host and not STATIC_NOISE.search(full) and ".js" in full:
            js_urls.append(full)
    js_urls = js_urls[:max_js]
    routes, gql = extract(html)
    with ThreadPoolExecutor(max_workers=min(12, max(2, len(js_urls)))) as ex:
        for r, g in ex.map(lambda u: extract(fetch(u)), js_urls):
            routes |= r; gql |= g
    # normalize to absolute-ish paths
    findings = []
    if routes:
        findings.append({"id": "deep-js-endpoints", "severity": "info",
                         "detail": f"{len(routes)} callable endpoint(s) extracted from the JS bundles — incl. unlinked/internal routes an attacker probes directly (often unauthenticated). Probe each.",
                         "endpoints": sorted(routes)[:80]})
    if gql:
        findings.append({"id": "embedded-graphql-operations", "severity": "info",
                         "detail": f"{len(gql)} embedded GraphQL operation(s) — feed to graphql_probe (works even with introspection off)",
                         "operations": sorted(gql)[:40]})
    return {"target": url, "ok": True, "js_files_scanned": len(js_urls), "endpoint_count": len(routes),
            "graphql_operations": len(gql), "endpoints": sorted(routes)[:120], "graphql_ops": sorted(gql)[:40],
            "findings": findings,
            "note": "deep/unlinked endpoints — test each directly (often reachable when not click-linked). urllib-blind through a JS-challenge WAF."}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Deep JS-endpoint extraction")
    ap.add_argument("url"); ap.add_argument("--max-js", type=int, default=25)
    a = ap.parse_args()
    print(json.dumps(sweep(a.url, a.max_js), indent=2))
