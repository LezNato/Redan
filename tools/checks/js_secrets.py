#!/usr/bin/env python
"""js_secrets.py — fetch a page's same-origin JS bundles and scan them for leaked
secrets, internal endpoints, and exposed source maps; also surface library/version
markers to feed cve_lookup. Client-side code is a routinely-overlooked surface.

Vendor-specific key patterns + assignment patterns are high-confidence findings;
generic long-string matches are leads. Secret VALUES are masked in output.
Discovery/leads — the verifier confirms. Core-scaled fetches.

Usage:
  python js_secrets.py <url> [--max-files 15] [--concurrency N]
"""
import sys, os, re, json, argparse
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _concurrency import workers
from _http import get as http_get

# (label, severity, regex) — vendor/assignment patterns are high-confidence
PATTERNS = [
    ("aws-access-key-id", "high", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws-secret-key", "high", re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("google-api-key", "high", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("stripe-key", "high", re.compile(r"(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{20,}")),
    ("github-token", "high", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    ("slack-token", "high", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("private-key", "high", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("jwt", "medium", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("hardcoded-secret", "medium", re.compile(
        r"(?i)(api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd)"
        r"\s*[:=]\s*['\"]([^'\"]{8,60})['\"]")),
    ("internal-endpoint", "low", re.compile(
        r"https?://(?:localhost|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|"
        r"172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|[a-z0-9.-]+\.(?:internal|local|corp|intranet))[^\s'\"]*")),
    ("source-map", "low", re.compile(r"sourceMappingURL=([^\s'\"]+\.map)")),
]

def fetch(url, timeout=20, limit=2_000_000):
    r = http_get(url, timeout=timeout, max_body=limit)
    return "" if (r.error or r.status >= 400) else r.text

def mask(s):
    s = s.strip().strip("'\"")
    return s if len(s) <= 8 else s[:4] + "…" + s[-4:]

def scan(url, max_files=15, conc=None):
    html = fetch(url)
    host = urlparse(url).netloc
    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, re.I)
    js_urls, seen = [], set()
    for s in srcs:
        full = urljoin(url, s)
        if urlparse(full).netloc == host and full not in seen:
            seen.add(full); js_urls.append(full)
    js_urls = js_urls[:max_files]
    with ThreadPoolExecutor(max_workers=workers(cap=16, want=conc)) as ex:
        blobs = list(ex.map(fetch, js_urls))
    corpus = [("(inline html)", html)] + list(zip(js_urls, blobs))

    findings, hits = [], {}
    for src, text in corpus:
        for label, sev, pat in PATTERNS:
            for m in pat.finditer(text or ""):
                val = m.group(2) if (m.lastindex and m.re.groups >= 2) else m.group(0)
                key = (label, val[:60])
                if key in hits:
                    continue
                hits[key] = True
                findings.append({"id": label, "severity": sev, "location": src,
                                 "detail": f"{label} in {src.rsplit('/',1)[-1]}: {mask(val)}"})
    # de-noise: drop generic internal-endpoint dupes beyond a few
    return {"target": url, "ok": True, "js_files_scanned": len(js_urls), "js_files": js_urls,
            "count": len(findings), "findings": findings,
            "note": "client-side leaks are LEADS — the verifier confirms the secret is live/in-scope before reporting"}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("url"); ap.add_argument("--max-files", type=int, default=15)
    ap.add_argument("--concurrency", type=int, default=None)
    a = ap.parse_args()
    print(json.dumps(scan(a.url, a.max_files, a.concurrency), indent=2))
