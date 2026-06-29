#!/usr/bin/env python
"""_result_cache.py — TTL result cache for IDEMPOTENT tool lookups.

Wraps a lookup so a repeat within the TTL returns the cached result without
re-hitting the source. Saves RoE budget (rate-limit, no-DoS) + speeds up verify
re-runs. Keyed by (tool_name, target, args_hash). Thread-safe. File-backed with
an mtime TTL (NOT an LRU — there is no eviction; call clear() to reset).

Use ONLY for idempotent lookups where a stale-but-valid answer is acceptable
(e.g. OSV CVE queries — wired into cve_lookup.osv). Do NOT cache active probes
whose whole point is a fresh observation (timing/race/boolean), and NEVER cache a
transient FAILURE as if it were an answer — pass `cache_if` to persist only good
results (a cached transient failure reads as a false 'clean').

Usage (as a module):
    from _result_cache import cached_run
    result, from_cache = cached_run("cve_lookup.osv", "npm/lodash", do_query,
                                    args_str="4.17.10", cache_if=lambda r: not r["transient_error"])

Or via CLI (manual cache inspect/clear):
    python _result_cache.py stats
    python _result_cache.py clear
"""
import hashlib, json, os, time, threading, sys

_CACHE_DIR = os.path.join(os.path.expanduser("~"), ".redan", "cache")
_MAX_AGE = 3600  # 1 hour TTL
_lock = threading.Lock()

def _key(tool, target, args_str=""):
    raw = f"{tool}|{target}|{args_str}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]

def _path(key):
    os.makedirs(_CACHE_DIR, exist_ok=True)
    return os.path.join(_CACHE_DIR, f"{key}.json")

def cached_run(tool_name, target, fn, args_str="", ttl=_MAX_AGE, cache_if=None):
    """Run fn() and cache its result; return (result, from_cache). On a fresh run,
    persist only when cache_if(result) is truthy (default: always) — pass a
    predicate to avoid caching transient failures as if they were answers."""
    k = _key(tool_name, target, args_str)
    p = _path(k)
    with _lock:
        if os.path.exists(p):
            age = time.time() - os.path.getmtime(p)
            if age < ttl:
                try:
                    with open(p, encoding="utf-8") as f:
                        return json.load(f), True  # (result, from_cache)
                except Exception:
                    pass  # corrupt cache entry -> fall through and recompute
    result = fn()
    if cache_if is None or cache_if(result):
        with _lock:
            try:
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(result, f)
            except Exception:
                pass  # caching is best-effort; never fail the lookup on a write error
    return result, False

def stats():
    if not os.path.isdir(_CACHE_DIR):
        return {"entries": 0, "size_kb": 0}
    files = [f for f in os.listdir(_CACHE_DIR) if f.endswith(".json")]
    size = sum(os.path.getsize(os.path.join(_CACHE_DIR, f)) for f in files)
    return {"entries": len(files), "size_kb": round(size / 1024, 1), "cache_dir": _CACHE_DIR}

def clear():
    if os.path.isdir(_CACHE_DIR):
        for f in os.listdir(_CACHE_DIR):
            if f.endswith(".json"):
                os.remove(os.path.join(_CACHE_DIR, f))
    return {"cleared": True}

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "stats"
    print(json.dumps({"stats": stats, "clear": clear}[cmd](), indent=2))
