#!/usr/bin/env python
"""crawler.py — same-origin crawler/spider for surface discovery (core-scaled).

BFS-crawls a seed URL (bounded depth + page cap), extracting links, FORMS (action +
inputs → fuzzing/IDOR targets), parameters, and URLs/endpoints referenced in JS.
Optionally authenticated via --cookie. Feeds discovered surface to web-tester /
fuzzer / sqlmap. Discovery only — no active exploitation.

Usage:
  python crawler.py <seed-url> [--depth 3] [--max-pages 120] [--cookie "k=v; k2=v2"] [--concurrency N]
"""
import sys, os, re, ssl, json, argparse, urllib.request, urllib.error
from urllib.parse import urljoin, urlparse, urldefrag
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _concurrency import workers

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
JS_ENDPOINT = re.compile(r"""["'`](/(?:api|graphql|rest|v\d|admin|user|account|auth)[A-Za-z0-9_\-/.{}]*)["'`]""")

def fetch(url, cookie=None, timeout=15):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    h = {"User-Agent": UA}
    if cookie: h["Cookie"] = cookie
    try:
        r = urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=timeout, context=ctx)
        return r.getcode(), r.headers.get("Content-Type", ""), r.read(400000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, "", ""
    except Exception:
        return None, "", ""

def _attr(name, s, default=None):  # handles quoted AND unquoted HTML attributes
    m = re.search(r'\b%s\s*=\s*(["\']?)([^"\'\s>]+)\1' % name, s, re.I)
    return m.group(2) if m else default

def parse_forms(html, base):
    forms = []
    for fm in re.finditer(r"<form\b(.*?)>(.*?)</form>", html, re.I | re.S):
        attrs, body = fm.group(1), fm.group(2)
        action = _attr("action", attrs, "")
        method = _attr("method", attrs, "get").upper()
        inputs = [m[1] for m in re.findall(
            r'<(?:input|textarea|select)\b[^>]*?\bname\s*=\s*(["\']?)([^"\'\s>]+)\1', body, re.I)]
        forms.append({"action": urljoin(base, action) if action else base, "method": method, "inputs": inputs})
    return forms

def crawl(seed, depth=3, max_pages=120, cookie=None, conc=None):
    host = urlparse(seed).netloc
    seen, pages, forms, params, endpoints = set(), [], [], set(), set()
    frontier = [urldefrag(seed)[0]]
    nworkers = workers(cap=24, want=conc)
    d = 0
    while frontier and len(seen) < max_pages and d <= depth:
        batch = [u for u in frontier if u not in seen][:max_pages - len(seen)]
        for u in batch:
            seen.add(u)
        with ThreadPoolExecutor(max_workers=nworkers) as ex:
            results = list(ex.map(lambda u: (u, fetch(u, cookie)), batch))
        nxt = set()
        for u, (status, ctype, html) in results:
            if status is None:
                continue
            pages.append({"url": u, "status": status})
            if "html" not in (ctype or "") and not html:
                continue
            for fobj in parse_forms(html, u):
                forms.append(fobj)
            for ep in JS_ENDPOINT.findall(html):
                endpoints.add(ep)
            for href in re.findall(r'(?:href|src)\s*=\s*["\']([^"\']+)["\']', html, re.I):
                full = urldefrag(urljoin(u, href))[0]
                pu = urlparse(full)
                if pu.netloc != host or not pu.scheme.startswith("http"):
                    continue
                if pu.query:
                    for kv in pu.query.split("&"):
                        if "=" in kv:
                            params.add((pu.path, kv.split("=", 1)[0]))
                if full not in seen and not re.search(r"\.(png|jpg|jpeg|gif|svg|css|woff2?|ico|pdf|zip)(\?|$)", full, re.I):
                    nxt.add(full)
        frontier = list(nxt); d += 1
    # dedup forms by (action, method, inputs)
    uniq, fkeys = [], set()
    for f in forms:
        k = (f["action"], f["method"], tuple(f["inputs"]))
        if k not in fkeys:
            fkeys.add(k); uniq.append(f)
    return {"target": seed, "ok": True, "pages_crawled": len(pages), "depth": d - 1,
            "concurrency": nworkers, "forms": uniq,
            "params": [{"path": p, "param": n} for p, n in sorted(params)],
            "js_endpoints": sorted(endpoints), "urls": [p["url"] for p in pages],
            "findings": [], "note": "surface map for web-tester/fuzzer/sqlmap — forms+params are injection/IDOR targets"}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("seed"); ap.add_argument("--depth", type=int, default=3)
    ap.add_argument("--max-pages", type=int, default=120); ap.add_argument("--cookie")
    ap.add_argument("--concurrency", type=int, default=None)
    a = ap.parse_args()
    print(json.dumps(crawl(a.seed, a.depth, a.max_pages, a.cookie, a.concurrency), indent=2))
