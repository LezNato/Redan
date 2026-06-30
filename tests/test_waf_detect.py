#!/usr/bin/env python
"""test_waf_detect.py — the channel router must NOT call a no-response target 'clean'.

A live engagement caught waf_detect reporting posture 'clean-or-passive' /
'reach directly' for a target that returned NO HTTP response on any probe — it was
actually per-IP graylisted (SYN-dropped). Concluding 'clean' there sends the tester
at a wall (a false negative, the inverse of the WAF-shell false positive). classify()
is pure, so this is a deterministic unit test of the routing decision."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "tools", "checks"))
from waf_detect import classify  # noqa: E402

CHECKS = []


def rec(name, ok, detail=""):
    CHECKS.append(bool(ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


def main():
    # classify(all_none, js_challenge, xhr_blocked, waf, nav_s) -> (posture, channel)
    # THE regression: all statuses null (no response) must NOT be 'clean-or-passive'
    posture, channel = classify(True, False, False, None, None)
    rec("all-null -> unreachable-or-graylisted (not 'clean')", posture == "unreachable-or-graylisted",
        posture)
    rec("graylisted channel steers to a fresh egress + browser",
        "proxy_rotate" in channel and "browser" in channel.lower())
    rec("graylisted channel does NOT say 'reach directly'", "reach the app directly" not in channel)

    # the other branches still classify correctly (regression guards)
    rec("challenge sig -> js-challenge", classify(False, True, False, "imunify", 200)[0] == "js-challenge")
    rec("genuinely clean -> clean-or-passive", classify(False, False, False, None, 200)[0] == "clean-or-passive")
    rec("xhr blocked -> xhr-blocked-waf", classify(False, False, True, None, 200)[0] == "xhr-blocked-waf")
    rec("waf banner, no challenge -> waf-present-passive",
        classify(False, False, False, "openresty", 200)[0] == "waf-present-passive")

    npass = sum(CHECKS)
    print(f"\n{npass}/{len(CHECKS)} checks passed")
    sys.exit(0 if npass == len(CHECKS) else 1)


if __name__ == "__main__":
    main()
