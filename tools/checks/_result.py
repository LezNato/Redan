#!/usr/bin/env python
"""_result.py — the canonical finder/probe output contract.

Tools historically ad-libbed their JSON shape; this is the one contract so an
agent can consume any probe uniformly and so the disposition vocabulary
(evidence-standard.md) is the SAME word in tool output as in the report.

Shape:
  {tool, target, ok, disposition, signals, verdict, results, note, ...extra}

  REQUIRED:    tool, target, ok (bool), disposition
  RECOMMENDED: signals (int), verdict (str), results (list), note (str)

disposition ∈ {confirmed, informational, lead, refuted, none}. A FINDER emits
`lead`/`none` by default — `confirmed` is the verifier's word (a tool may only
emit it with a paired-control/content proof; see doctrine_lint C1). `refuted`
records a killed false positive.

Usage in a tool:
    from _result import emit
    emit("cors_probe", url, disposition="lead" if hits else "none",
         signals=len(hits), verdict="reflected-origin + credentials", results=hits,
         note="CWE-942; verify with credentialed cross-origin fetch")

emit() is OPTIONAL — a tool may print a hand-built dict that conforms to the shape
(the rewritten probes do). Conformance is enforced externally by validate_result()
in tests/test_tool_contract.py, not by importing this helper.
"""
import json

DISPOSITIONS = {"confirmed", "informational", "lead", "refuted", "none"}


def result(tool, target, ok=True, disposition="none", signals=0, verdict="",
           results=None, note="", **extra):
    d = {"tool": tool, "target": target, "ok": bool(ok), "disposition": disposition,
         "signals": signals, "verdict": verdict, "results": results or [], "note": note}
    d.update(extra)
    return d


def validate_result(d):
    """Return a list of contract violations ([] = conforms). Required fields +
    a valid disposition; recommended fields are not enforced."""
    errs = []
    for k in ("tool", "target", "ok", "disposition"):
        if k not in d:
            errs.append(f"missing required field '{k}'")
    if "ok" in d and not isinstance(d["ok"], bool):
        errs.append("'ok' must be a bool")
    if d.get("disposition") not in DISPOSITIONS:
        errs.append(f"disposition {d.get('disposition')!r} not in {sorted(DISPOSITIONS)}")
    if "signals" in d and not isinstance(d["signals"], int):
        errs.append("'signals' must be an int")
    if "results" in d and not isinstance(d["results"], list):
        errs.append("'results' must be a list")
    return errs


def emit(tool, target, **kw):
    """Build + print the canonical result JSON (the tool's stdout contract)."""
    print(json.dumps(result(tool, target, **kw), indent=2))
