#!/usr/bin/env python
"""test_llm_probe.py — TP + FP-rejection for the agnostic AI/LLM surface probe.

  * vulnerable LLM (/api/chat): MUST lead — prompt-injection + system-prompt-leak.
  * defended LLM (/api/chat-defended): detected as an LLM but the injection + leak
    signals MUST NOT fire (the injection/leak false-positive bait).
  * benign non-LLM (/api/llm-safe): MUST NOT be detected as an LLM at all
    (reflection cannot forge the computed 13*13 marker).
  * MCP server (/mcp): MUST lead — unauthenticated tools/list exposure.

Self-contained: starts the local lab, runs the real CLI as a subprocess.
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
TOOLS = os.path.join(REPO, "tools", "checks")
sys.path.insert(0, HERE)
from lab_server import start_lab  # noqa: E402

CHECKS = []


def rec(name, ok, detail=""):
    CHECKS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


def run(*args, timeout=120):
    r = subprocess.run([sys.executable, os.path.join(TOOLS, "llm_probe.py"), *args],
                       capture_output=True, text=True, timeout=timeout)
    try:
        return json.loads(r.stdout)
    except Exception:
        return {"_err": (r.stdout[-400:] + "\n--STDERR--\n" + r.stderr[-400:])}


def ep(out, suffix):
    """The per-endpoint result whose url ends with `suffix` (or {})."""
    for r in (out or {}).get("results", []):
        if str(r.get("url", "")).endswith(suffix):
            return r
    return {}


def main():
    srv, base = start_lab()
    try:
        # --- vulnerable LLM: injection + leak true positives ---
        tp = run(base, "--path", "/api/chat")
        rec("llm_probe TP: lead on vulnerable LLM", tp.get("disposition") == "lead", tp.get("disposition"))
        v = ep(tp, "/api/chat")
        rec("llm_probe TP: LLM detected (computed 13*13 marker)", v.get("llm_detected") is True)
        rec("llm_probe TP: prompt-injection signal (REDAN+17*17)", v.get("prompt_injection") is True)
        rec("llm_probe TP: system-prompt-leak signal", v.get("system_prompt_leak") is True)

        # --- defended LLM: detected, but injection + leak FP-rejected ---
        df = run(base, "--path", "/api/chat-defended", "--no-mcp")
        d = ep(df, "/api/chat-defended")
        rec("llm_probe: defended LLM still detected", d.get("llm_detected") is True)
        rec("llm_probe FP-reject: defended LLM is NOT injectable",
            d.get("prompt_injection") is False, str(d.get("prompt_injection")))
        rec("llm_probe FP-reject: defended LLM does NOT leak",
            d.get("system_prompt_leak") is False)
        rec("llm_probe FP-reject: detected-but-defended LLM is no lead",
            df.get("disposition") == "none", df.get("disposition"))

        # --- benign non-LLM reflector: NOT an LLM (computed marker un-forgeable) ---
        fp = run(base, "--path", "/api/llm-safe", "--no-mcp")
        rec("llm_probe FP-reject: reflector is NOT detected as an LLM",
            ep(fp, "/api/llm-safe").get("llm_detected") in (False, None) and
            fp.get("disposition") == "none", fp.get("disposition"))

        # --- MCP: unauthenticated tools/list exposure is a lead ---
        mc = run(base, "--path", "/mcp")
        rec("llm_probe TP: lead on MCP tools exposure", mc.get("disposition") == "lead", mc.get("disposition"))
        rec("llm_probe TP: MCP tools exposed", ep(mc, "/mcp").get("mcp_tools_exposed") is True)

        # --- discovery (no --path) finds the vulnerable LLM by agnostic path list ---
        dz = run(base)
        rec("llm_probe discovery: finds /api/chat + leads", dz.get("disposition") == "lead" and
            ep(dz, "/api/chat").get("llm_detected") is True, dz.get("disposition"))
    finally:
        srv.shutdown()

    npass = sum(CHECKS)
    print(f"\n{npass}/{len(CHECKS)} checks passed")
    sys.exit(0 if npass == len(CHECKS) else 1)


if __name__ == "__main__":
    main()
