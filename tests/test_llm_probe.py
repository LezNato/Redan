#!/usr/bin/env python
"""test_llm_probe.py — TP + FP-rejection for the agnostic AI/LLM surface probe.

  * vulnerable LLM (/api/chat): MUST lead — prompt-injection (battery), a Base64
    filter-bypass variant, system-prompt-leak, and (with --oob) tool-abuse.
  * defended LLM (/api/chat-defended): detected as an LLM but injection / multi-turn /
    indirect / leak / tool-abuse signals MUST NOT fire (the false-positive bait).
  * guarded LLM (/api/chat-guarded): refuses the single-shot override but a multi-turn
    Crescendo ramp slips it past — MUST flag multi_turn_injection (bypassed_singleshot).
  * RAG LLM (/api/rag): trusts a 'retrieved data' field — MUST flag indirect_injection;
    its data-sandboxing twin (/api/rag-safe) MUST NOT (the indirect false-positive bait).
  * benign non-LLM (/api/llm-safe): MUST NOT be detected as an LLM at all
    (reflection cannot forge the computed 13*13 marker).
  * MCP server (/mcp): MUST lead — unauthenticated tools/list exposure AND a
    poisoned tool description.

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
        # --- vulnerable LLM: injection (battery + encoded bypass) + leak ---
        tp = run(base, "--path", "/api/chat", "--no-mcp")
        rec("llm_probe TP: lead on vulnerable LLM", tp.get("disposition") == "lead", tp.get("disposition"))
        v = ep(tp, "/api/chat")
        rec("llm_probe TP: LLM detected (computed 13*13 marker)", v.get("llm_detected") is True)
        rec("llm_probe TP: prompt-injection signal (REDAN+17*17)", v.get("prompt_injection") is True)
        rec("llm_probe TP: Base64 filter-bypass variant fires", bool(v.get("injection_filter_bypass")),
            str(v.get("injection_filter_bypass")))
        rec("llm_probe TP: system-prompt-leak signal", v.get("system_prompt_leak") is True)

        # --- vulnerable LLM with --oob: tool-abuse / excessive-agency callback ---
        ab = run(base, "--path", "/api/chat", "--no-mcp", "--oob", "--oob-host", "127.0.0.1")
        rec("llm_probe TP: tool-abuse OOB callback (excessive agency)",
            ep(ab, "/api/chat").get("tool_abuse") is True, str(ep(ab, "/api/chat").get("tool_abuse")))

        # --- defended LLM: detected, but injection + leak + tool-abuse FP-rejected ---
        df = run(base, "--path", "/api/chat-defended", "--no-mcp", "--oob", "--oob-host", "127.0.0.1")
        d = ep(df, "/api/chat-defended")
        rec("llm_probe: defended LLM still detected", d.get("llm_detected") is True)
        rec("llm_probe FP-reject: defended LLM is NOT injectable",
            d.get("prompt_injection") is False, str(d.get("prompt_injection")))
        rec("llm_probe FP-reject: defended LLM resists multi-turn/Crescendo",
            d.get("multi_turn_injection") is False, str(d.get("multi_turn_injection")))
        rec("llm_probe FP-reject: defended LLM resists indirect injection",
            d.get("indirect_injection") is False, str(d.get("indirect_injection")))
        rec("llm_probe FP-reject: defended LLM does NOT leak", d.get("system_prompt_leak") is False)
        rec("llm_probe FP-reject: defended LLM does NOT abuse tools", d.get("tool_abuse") is False)
        rec("llm_probe FP-reject: detected-but-defended LLM is no lead",
            df.get("disposition") == "none", df.get("disposition"))

        # --- multi-turn / Crescendo: single-shot REFUSED but the ramp slips it past ---
        gd = run(base, "--path", "/api/chat-guarded", "--no-mcp")
        g = ep(gd, "/api/chat-guarded")
        rec("llm_probe TP: multi-turn/Crescendo injection fires", g.get("multi_turn_injection") is True,
            str(g.get("multi_turn_injection")))
        rec("llm_probe: guarded LLM refuses the SINGLE-SHOT override (distinct from multi-turn)",
            g.get("prompt_injection") is False, str(g.get("prompt_injection")))
        rec("llm_probe TP: multi-turn flagged as bypassing the single-shot guardrail",
            g.get("multi_turn_bypassed_singleshot") is True)
        rec("llm_probe TP: guarded LLM is a lead (via multi-turn)", gd.get("disposition") == "lead",
            gd.get("disposition"))

        # --- indirect / data-channel: instruction hidden in 'retrieved' data executes ---
        rg = run(base, "--path", "/api/rag", "--no-mcp")
        rec("llm_probe TP: indirect (data-channel) injection fires",
            ep(rg, "/api/rag").get("indirect_injection") is True, str(ep(rg, "/api/rag").get("indirect_injection")))
        rec("llm_probe TP: RAG endpoint is a lead", rg.get("disposition") == "lead", rg.get("disposition"))
        # data-sandboxing endpoint: the SAME hidden instruction must NOT fire from the data channel
        rs = run(base, "--path", "/api/rag-safe", "--no-mcp")
        rec("llm_probe FP-reject: data-sandboxing LLM resists indirect injection",
            ep(rs, "/api/rag-safe").get("indirect_injection") is False,
            str(ep(rs, "/api/rag-safe").get("indirect_injection")))

        # --- benign non-LLM reflector: NOT an LLM (computed marker un-forgeable) ---
        fp = run(base, "--path", "/api/llm-safe", "--no-mcp")
        rec("llm_probe FP-reject: reflector is NOT detected as an LLM",
            ep(fp, "/api/llm-safe").get("llm_detected") in (False, None) and
            fp.get("disposition") == "none", fp.get("disposition"))

        # --- MCP: unauthenticated tools/list exposure + tool-description poisoning ---
        mc = run(base, "--path", "/mcp")
        rec("llm_probe TP: lead on MCP exposure", mc.get("disposition") == "lead", mc.get("disposition"))
        rec("llm_probe TP: MCP tools exposed", ep(mc, "/mcp").get("mcp_tools_exposed") is True)
        rec("llm_probe TP: MCP tool-poisoning detected", ep(mc, "/mcp").get("mcp_tool_poisoning") is True)

        # --- discovery (no --path) finds the vulnerable LLM by agnostic path list ---
        dz = run(base, "--no-mcp")
        rec("llm_probe discovery: finds /api/chat + leads", dz.get("disposition") == "lead" and
            ep(dz, "/api/chat").get("llm_detected") is True, dz.get("disposition"))
    finally:
        srv.shutdown()

    npass = sum(CHECKS)
    print(f"\n{npass}/{len(CHECKS)} checks passed")
    sys.exit(0 if npass == len(CHECKS) else 1)


if __name__ == "__main__":
    main()
