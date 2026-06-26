#!/usr/bin/env python
"""flow_probe.py — business-logic / workflow-abuse probe (stdlib only).

Business-logic flaws (skip-the-payment, double-coupon, negative-quantity, price-tamper, step-
reorder) are the #1 creative-attacker target once the obvious CVEs are patched — and the kit had
zero coverage. This tool takes a recorded step-list of the INTENDED multi-step flow (cart -> coupon
-> checkout -> payment) and replays it with attacker variations:
  - skip each step (does the flow complete without step X? skip-the-payment)
  - tamper numeric fields (quantity/price/currency/coupon/amount -> -1, 0, 99999)
  - reorder (payment before checkout)
then DIFFS the outcome (status + body) vs the baseline. A diff = a potential business-logic
flaw (LEAD — the INTENT interpretation is the opus agent's; the tool replays + diffs).

Usage: python flow_probe.py --steps <steps.json> [--insecure]
  steps.json: [{"method":"POST","url":"...","body":{"k":"v"},"headers":{...}}, ...]
  (body is a JSON dict; the LAST step's response is the "outcome" that's diffed.)
"""
import sys, json, ssl, copy, hashlib, argparse, urllib.request, urllib.error

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
_CTX = ssl.create_default_context(); _CTX.check_hostname = False; _CTX.verify_mode = ssl.CERT_NONE
TAMPER_FIELDS = ("quantity", "qty", "price", "amount", "currency", "coupon", "discount", "total", "subtotal", "shipping")
TAMPER_VALUES = [-1, 0, 99999, ""]
COOKIE_JAR = []  # accumulate Set-Cookie across steps (maintain session within a replay)

def fire(step, verify=True, cookie_jar=None):
    body = step.get("body")
    data = None
    h = {"User-Agent": UA, "Accept": "*/*"}; h.update(step.get("headers", {}))
    if body is not None:
        if "Content-Type" in {k.lower() for k in h} and "json" not in h.get("Content-Type", "").lower():
            import urllib.parse as up; data = up.urlencode(body).encode()
        else:
            h.setdefault("Content-Type", "application/json"); data = json.dumps(body).encode()
    if cookie_jar:
        h["Cookie"] = "; ".join(cookie_jar)
    try:
        r = urllib.request.urlopen(urllib.request.Request(step["url"], data=data, method=step.get("method", "POST"), headers=h),
                                   timeout=20, context=(_CTX if not verify else None))
        sc = r.headers.get_all("Set-Cookie") or []
        if cookie_jar is not None:
            for c in sc: cookie_jar.append(c.split(";")[0])
        return r.status, r.read(4000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(4000).decode("utf-8", "replace")
    except Exception as e:
        return None, str(e)

def outcome(steps, verify):
    jar = []
    for s in steps:
        st, body = fire(s, verify, jar)
    return {"status": st, "body_sha": hashlib.sha256(body.encode()).hexdigest()[:12], "body_head": body[:150]}

def diff_strong(baseline, variant):
    return baseline["body_sha"] != variant["body_sha"] or baseline["status"] != variant["status"]

def run(steps, verify):
    findings = []
    baseline = outcome(steps, verify)
    # skip-each-step: replay without step i (does the flow still "succeed"?)
    for i in range(len(steps)):
        if len(steps) <= 1: break
        variant_steps = steps[:i] + steps[i+1:]
        var = outcome(variant_steps, verify)
        if diff_strong(baseline, var) and var["status"] and 200 <= var["status"] < 300:
            findings.append({"id": "business-logic-skip-step", "severity": "high",
                             "detail": f"the flow COMPLETED (HTTP {var['status']}) even when step {i} ({steps[i].get('method','')} {steps[i]['url']}) was SKIPPED — a step the intended flow requires is not enforced server-side (e.g. skip-the-payment, skip-the-auth-check). Confirm the step was meant to be mandatory.",
                             "skipped_step": i, "variant_outcome": var})
    # tamper numeric fields: for each step with a body containing a tamperable field, set to each value
    for i, s in enumerate(steps):
        body = s.get("body")
        if not isinstance(body, dict): continue
        for k, v in list(body.items()):
            if k.lower() in TAMPER_FIELDS:
                for tv in TAMPER_VALUES:
                    tampered = copy.deepcopy(steps)
                    tampered[i] = {**s, "body": {**body, k: tv}}
                    var = outcome(tampered, verify)
                    if diff_strong(baseline, var) and var["status"] and 200 <= var["status"] < 300:
                        findings.append({"id": "business-logic-field-tamper", "severity": "high",
                                         "detail": f"setting '{k}'={tv!r} at step {i} was ACCEPTED (HTTP {var['status']}, outcome differs from baseline) — the server trusts client-stated {k}. Confirm this violates the intended business rule (e.g. negative quantity, price=0, coupon-stacking).",
                                         "step": i, "field": k, "value": tv, "variant_outcome": var})
    return {"ok": True, "steps_count": len(steps), "baseline_outcome": baseline, "findings": findings,
            "note": "business-logic LEADS — a diff means the server accepted an unintended flow/field-value; the opus agent must interpret whether it violates the documented intent (pitfalls: an accepted coupon/price is not a bug unless it violates intent)."}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Business-logic / workflow-abuse probe")
    ap.add_argument("--steps", required=True, help="JSON file: [{method,url,body,headers}, ...]")
    ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()
    steps = json.load(open(a.steps, encoding="utf-8"))
    print(json.dumps(run(steps, not a.insecure), indent=2))
