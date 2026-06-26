#!/usr/bin/env python
"""graphql_probe.py — detect a GraphQL endpoint, run introspection, and flag the
common GraphQL exposures.

Tries common endpoint paths, sends a minimal introspection query, and (if enabled)
enumerates types/queries/mutations. Flags: introspection enabled (info leak),
exposed mutations (authz/abuse surface), and suggestive sensitive types/fields.
Candidate findings/leads — the verifier confirms object-level access.

Usage:
  python graphql_probe.py <base-url-or-graphql-url>
"""
import sys, os, re, ssl, json, argparse, urllib.request, urllib.error

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
PATHS = ["", "/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1", "/query", "/graphiql", "/api/gql"]
INTROSPECT = {"query": "query{__schema{queryType{name} mutationType{name} types{name kind fields{name}}}}"}
SENSITIVE = re.compile(r"(?i)(password|passwd|secret|token|ssn|creditcard|credit_card|apikey|api_key|private|admin|role|isadmin)")

def post(url, payload, timeout=15):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"User-Agent": UA, "Content-Type": "application/json"})
    try:
        r = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return r.getcode(), r.read(500000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read(20000).decode("utf-8", "replace") if hasattr(e, "read") else "")
    except Exception:
        return None, ""

def probe(target):
    target = target.replace("//localhost", "//127.0.0.1").rstrip("/")
    # build candidate endpoints
    if re.search(r"/(graphql|gql|query)", target, re.I):
        candidates = [target]
    else:
        candidates = [target + p for p in PATHS]
    endpoint = None
    body = ""
    for u in candidates:
        status, b = post(u, INTROSPECT)
        if status and ("__schema" in b or '"data"' in b or "errors" in b and "query" in b.lower()):
            endpoint = u; body = b
            if "__schema" in b:
                break
    if not endpoint:
        return {"target": target, "ok": True, "graphql_found": False, "findings": [],
                "note": "no GraphQL endpoint responded to introspection on common paths"}
    introspection_enabled = "__schema" in body
    findings, queries, mutations, types = [], [], [], []
    if introspection_enabled:
        try:
            data = json.loads(body).get("data", {}).get("__schema", {})
            mutation_type = (data.get("mutationType") or {}).get("name")
            for t in data.get("types", []):
                if t.get("name", "").startswith("__"):
                    continue
                types.append(t["name"])
                for f in (t.get("fields") or []):
                    if t["name"] == mutation_type:
                        mutations.append(f["name"])
        except Exception:
            pass
        findings.append({"id": "graphql-introspection-enabled", "severity": "low", "cwe": "CWE-200",
                         "location": endpoint,
                         "detail": f"GraphQL introspection is enabled — full schema disclosed "
                                   f"({len(types)} types, {len(mutations)} mutations)"})
        sens = sorted(set(t for t in types if SENSITIVE.search(t)))
        if sens:
            findings.append({"id": "graphql-sensitive-types", "severity": "low", "location": endpoint,
                             "detail": f"sensitive-looking types exposed (verify object-level access): {', '.join(sens[:10])}"})
        if mutations:
            findings.append({"id": "graphql-mutations-exposed", "severity": "info", "location": endpoint,
                             "detail": f"{len(mutations)} mutations exposed — review authz (LEAD): {', '.join(mutations[:10])}"})
    return {"target": target, "ok": True, "graphql_found": True, "endpoint": endpoint,
            "introspection_enabled": introspection_enabled, "types": len(types),
            "mutations": mutations[:30], "findings": findings,
            "note": "introspection/mutations are LEADS — verifier confirms object/field-level access control"}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    a = ap.parse_args()
    print(json.dumps(probe(a.url), indent=2))
