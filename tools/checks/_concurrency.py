#!/usr/bin/env python
"""_concurrency.py — core-scaled worker counts for the deterministic check tools.

The LLM agent layer is bounded by the harness (min(16, cores-2) concurrent
agents). The deterministic tools below have no such cap and should use the box.
Network checks are I/O-bound (threads mostly wait on sockets), so we oversubscribe
relative to cores, bounded by a per-tool cap and overridable with --concurrency.

NOTE for ACTIVE tools: higher concurrency = more simultaneous load on the target.
Keep it polite on production / rate-limited targets (lower --concurrency); go wide
on labs and CDN-fronted hosts.
"""
import os

def cpus():
    return os.cpu_count() or 4

def workers(io_bound=True, cap=64, want=None):
    """Default worker count. io_bound -> cores*4 (waits on network); else cores.
    `cap` bounds it; `want` (e.g. from --concurrency) overrides when >0."""
    if want and want > 0:
        return min(want, 512)
    n = cpus()
    base = n * 4 if io_bound else n
    return max(2, min(cap, base))
