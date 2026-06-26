#!/usr/bin/env python
"""_result_cache.py — LRU result cache for deterministic tools.

Wraps tool execution so repeated/duplicate probes return cached results without
re-hitting the target. Saves RoE budget (rate-limit, no-DoS) + speeds up verify
re-runs. Keyed by (tool_name, target_url, args_hash). Thread-safe.

Usage (as a module):
    from _result_cache import cached_run
    result = cached_run("http_headers", "https://example.com", lambda: run_check("https://example.com"))
    # second call with same args returns the cached result instantly

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

def cached_run(tool_name, target, fn, args_str="", ttl=_MAX_AGE):
    """Run fn() and cache the result; return cached on repeat within TTL."""
    k = _key(tool_name, target, args_str)
    p = _path(k)
    with _lock:
        if os.path.exists(p):
            age = time.time() - os.path.getmtime(p)
            if age < ttl:
                with open(p, encoding="utf-8") as f:
                    return json.load(f), True  # (result, from_cache)
    result = fn()
    with _lock:
        with open(p, "w", encoding="utf-8") as f:
            json.dump(result, f)
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
