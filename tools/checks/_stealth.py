#!/usr/bin/env python
"""_stealth.py — shared stealth-request helpers (stdlib only).

The audit flagged that the kit uses a literal "authorized-recon" UA (a beacon — announces recon),
cores×4 concurrent bursts, no jitter, single source IP. A real attacker blends (rotating UAs,
jittered timing, header-order randomization, proxy rotation). This module is the opt-in stealth
layer; tools import it and pass --stealth to reduce the detection footprint.

  ua()               -> a realistic desktop browser UA (NOT a beacon)
  jitter(lo=0.2, hi=1.5) -> sleep a random float seconds (inter-request pacing)
  shuffled_headers(base) -> the base headers in a randomized key order (minor TLS/HTTP fingerprint diversity)
  proxy()            -> the HTTPS_PROXY env (or a pool if STEALTH_PROXY_POOL set) for egress rotation

Usage (in a tool):  from _stealth import ua, jitter; hdrs = {"User-Agent": ua()}; jitter()
"""
import os, random, time

# realistic, current-ish desktop browser UAs (not a tool-identifying / bot / scanner UA)
_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Edg/124.0.0.0",
]

def ua():
    return random.choice(_UA_POOL)

def jitter(lo=0.2, hi=1.5):
    time.sleep(random.uniform(lo, hi))

def shuffled_headers(base):
    """Return base dict as a new dict with randomized insertion order (urllib sends in insertion order)."""
    items = list(base.items()); random.shuffle(items)
    return dict(items)

def proxy():
    """Return a proxy URL for egress rotation, or None. Reads STEALTH_PROXY_POOL (comma-list) or HTTPS_PROXY."""
    pool = os.environ.get("STEALTH_PROXY_POOL")
    if pool:
        return random.choice([p.strip() for p in pool.split(",") if p.strip()])
    return os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
