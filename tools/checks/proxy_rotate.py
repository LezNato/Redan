#!/usr/bin/env python
"""proxy_rotate.py — find a live, non-graylisted egress proxy for a target (stdlib).

When a target's edge (Imunify360/Cloudflare-class) graylists your source IP at the TCP
layer, every urllib/curl/nuclei request times out — not because the site is down, but
because YOUR IP is dropped. A different source IP restores reachability. This tool sources
free PUBLIC HTTP proxies (TheSpeedX/PROXY-List, ProxyScrape), tests them in parallel
against the target, and returns the ones that got a real HTTP response (the graylist is
beaten at the network layer).

PAIR WITH THE BROWSER CHANNEL for JS-challenge edges: a proxy restores TCP reach but
CANNOT solve a JS proof-of-work ("One moment, please..."). For a JS-challenge WAF, route a
headless Chromium through the proxy returned here (`browser_probe.py --proxy ...`) — the
browser solves the PoW, then same-origin fetches reach the real app. (methodology.md →
"Edge-WAF channel routing".) A `challenge: true` hit means the edge served an interstitial;
the proxy reached it, but the deterministic (urllib) tools will still be blind.

RoE / DATA-HANDLING — read this: free public proxies are run by UNKNOWN operators who can
observe or MITM your traffic. Use ONLY for recon/testing of targets you're authorized to
test, and NEVER route credentials, session tokens, or user PII through them. This is opt-in;
the kit does not enable it by default. (rules-of-engagement.md → third-party-shared-infra
caution; pitfalls.md → confirm-through-the-browser.)

Usage:
  python proxy_rotate.py <target-url> [--count 80] [--source both|speedx|proxyscrape|<url>] [--timeout 7] [--insecure]
"""
import sys, os, re, json, ssl, time, random, argparse, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _concurrency import workers

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
_CTX = ssl.create_default_context(); _CTX.check_hostname = False; _CTX.verify_mode = ssl.CERT_NONE
NAMED = {
    "speedx": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "proxyscrape": "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=4000&country=all&ssl=all&anonymity=all",
}
CHALLENGE_MARKERS = ("one moment", "checking your browser", "just a moment", "imunify", "challenge-platform", "attention required", "cf-chl")


def _title(body):
    m = re.search(r"<title>(.*?)</title>", body or "", re.I | re.S)
    return (m.group(1).strip()[:80] if m else "")


def _fetch_list(source, timeout=20):
    url = NAMED.get(source, source)  # named source, else treat as a raw URL
    try:
        return [l.strip() for l in urllib.request.urlopen(url, timeout=timeout, context=_CTX).read().decode("latin-1", "replace").split() if l.strip()]
    except Exception:
        return []


def _test(proxy, target, timeout, verify):
    ph = urllib.request.ProxyHandler({"http": "http://" + proxy, "https": "http://" + proxy})
    https = urllib.request.HTTPSHandler(context=(ssl.create_default_context() if verify else _CTX))  # --insecure now actually applies CERT_NONE
    op = urllib.request.build_opener(ph, https)
    t0 = time.perf_counter()
    try:
        r = op.open(urllib.request.Request(target, headers={"User-Agent": UA}), timeout=timeout)
        body = r.read(1000).decode("latin-1", "replace")
        return {"proxy": proxy, "status": r.status, "server": r.headers.get("Server", ""),
                "challenge": any(m in body.lower() for m in CHALLENGE_MARKERS),
                "title": _title(body), "latency_ms": round((time.perf_counter() - t0) * 1000)}
    except urllib.error.HTTPError as e:
        # ANY HTTP response = the proxy reached the target's edge (TCP graylist beaten)
        body = e.read(400).decode("latin-1", "replace") if hasattr(e, "read") else ""
        return {"proxy": proxy, "status": e.code, "server": (e.headers or {}).get("Server", ""),
                "challenge": any(m in body.lower() for m in CHALLENGE_MARKERS),
                "title": _title(body), "latency_ms": round((time.perf_counter() - t0) * 1000)}
    except Exception:
        return None


def run(target, count, source, timeout, verify):
    sources = ["speedx", "proxyscrape"] if source == "both" else [source]
    proxies = []
    for s in sources:
        proxies.extend(_fetch_list(s))
    proxies = list(dict.fromkeys(proxies))  # de-dup, preserve order
    sample = random.sample(proxies, min(count, len(proxies))) if proxies else []
    out = {"target": target, "ok": bool(sample), "sources": sources, "pool_size": len(proxies),
           "candidates_tested": len(sample), "hits": [], "hits_count": 0}
    if not sample:
        out["note"] = "no proxy list fetched (no network egress to the list source?) — cannot rotate"
        return out
    t0 = time.perf_counter()
    hits = []
    with ThreadPoolExecutor(max_workers=workers(cap=40)) as ex:
        for res in ex.map(lambda px: _test(px, target, timeout, verify), sample):
            if res:
                hits.append(res)
    # rank: non-challenge first, then 2xx, then by latency
    hits.sort(key=lambda h: (1 if h["challenge"] else 0, 0 if (h["status"] or 0) < 300 else 1, h["latency_ms"]))
    out["hits"] = hits
    out["hits_count"] = len(hits)
    out["elapsed_ms"] = round((time.perf_counter() - t0) * 1000)
    out["note"] = ("free-public-proxy egress rotation. A hit = the proxy reached the target's edge (TCP graylist "
                   "beaten). challenge=true => the edge served a JS/interstitial — the deterministic urllib tools stay "
                   "BLIND; route the BROWSER channel through this proxy (browser_probe.py --proxy) to solve the PoW. "
                   "RoE: NEVER route credentials/tokens/PII through free public proxies.")
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Find a live, non-graylisted egress proxy for a target")
    ap.add_argument("target", help="target URL to reach (e.g. https://example.com/)")
    ap.add_argument("--count", type=int, default=80, help="proxies to test")
    ap.add_argument("--source", default="both", help="speedx | proxyscrape | both | <list-URL>")
    ap.add_argument("--timeout", type=int, default=7, help="per-proxy test timeout (s)")
    ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()
    print(json.dumps(run(a.target, a.count, a.source, a.timeout, not a.insecure), indent=2))
