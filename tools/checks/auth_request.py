#!/usr/bin/env python
"""auth_request.py — authenticated requester (READ-ONLY by default) + IDOR oracle.

Loads a role's session from out-of-tree storage (never argv). Two modes:

  single   one request as a role. Re-checks SESSION LIVENESS first (a dead session
           silently testing logged-out is the worst false-negative) and emits a
           structured evidence record (status, body hash/len, session_valid,
           canary_present, cache indicator) — not an LLM's recollection.

  --idor   the 4-CELL oracle that kills "200 == IDOR": fetch an object as the
           OWNER (baseline canary), the OTHER role, ANON, and the OTHER role on a
           bogus id (control). Verdict = confirmed ONLY if the other role's body
           carries the owner's canary, anon does NOT (else it is public, not an
           authz bug), the other session is live, and the response differs from
           the bogus-id control.

Method allowlist: GET/HEAD/OPTIONS. Mutations require --allow-mutation AND the
engagement's mutation-gate approval (defense in depth). Canary raw value is never
emitted (only presence + sha256). Use --save to write a REDACTED transcript.

Usage:
  python auth_request.py --engagement E --role A [--method GET] [--canary V] [--save F] <url>
  python auth_request.py --engagement E --idor --owner A --other B --canary V <url>
  python auth_request.py --engagement E --role anon <url>          # unauthenticated arm
"""
import sys, os, re, json, argparse, hashlib
from http.cookiejar import MozillaCookieJar
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _authlib as A

SAFE = {"GET", "HEAD", "OPTIONS"}

def load_session(engagement, roles, role_name):
    """Return (role_dict|None, cookiejar, bearer, extra_headers)."""
    if role_name == "anon":
        return None, None, None, {}
    role = A.get_role(roles, role_name)
    rtype = role.get("type", "form")
    if rtype == "form":
        jar = MozillaCookieJar()
        sp = A.session_path(engagement, role_name)
        if os.path.exists(sp):
            jar.load(sp, ignore_discard=True, ignore_expires=True)
        return role, jar, None, {}
    if rtype == "json":
        tok = A.load_token(engagement, role_name)
        if not tok:
            raise FileNotFoundError(f"no acquired token for role '{role_name}' — run "
                                    f"auth_login --engagement {engagement} --role {role_name} first")
        return role, None, tok, {}
    if rtype == "token":
        return role, None, A.secret(role, "token"), {}
    if rtype == "storage_state":
        ss = role.get("storage_state")
        cookies = []
        try:
            data = json.load(open(ss, encoding="utf-8"))
            cookies = data.get("cookies", [])
        except Exception:
            pass
        hdr = "; ".join(f"{c['name']}={c['value']}" for c in cookies if c.get("name"))
        return role, None, None, ({"Cookie": hdr} if hdr else {})
    return role, None, None, {}

def evidence(role_name, url, method, r, canary):
    body = r["body"] or b""
    txt = body.decode("utf-8", "replace")
    ev = {"role": role_name, "url": url, "method": method, "status": r["status"],
          "final_url": r["final_url"], "body_len": len(body),
          "body_sha256": hashlib.sha256(body).hexdigest()[:16], "error": r["error"]}
    h = {k.lower(): v for k, v in (r["headers"] or {}).items()}
    ci = {k: h[k] for k in ("age", "x-cache", "cf-cache-status") if k in h}
    if ci: ev["cache_indicator"] = ci
    if canary is not None:
        ev["canary_present"] = canary in txt
        ev["canary_sha256"] = hashlib.sha256(canary.encode()).hexdigest()[:12]
    return ev

def bogus(url):
    if re.search(r'/\d+(?:/?$|\?)', url):
        return re.sub(r'/(\d+)(/?$|\?)', r'/987654321\2', url, count=1)
    sep = "&" if "?" in url else "?"
    return url + sep + "pt_bogus_id=987654321"

def one(engagement, roles, role_name, url, method="GET", canary=None, verify=True):
    role, jar, bearer, hdrs = load_session(engagement, roles, role_name)
    valid, ldetail = (True, "anon") if role_name == "anon" else A.liveness(role, cookiejar=jar, bearer=bearer, verify=verify)
    r = A.request(url, method, cookiejar=jar, bearer=bearer, headers=hdrs, verify=verify)
    ev = evidence(role_name, url, method, r, canary)
    ev["session_valid"] = valid
    ev["session_detail"] = ldetail
    return ev, r

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--engagement", required=True)
    ap.add_argument("--role")
    ap.add_argument("--method", default="GET")
    ap.add_argument("--canary")
    ap.add_argument("--save")
    ap.add_argument("--allow-mutation", action="store_true")
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--idor", action="store_true")
    ap.add_argument("--owner")
    ap.add_argument("--other")
    ap.add_argument("--funclevel", action="store_true")
    ap.add_argument("--endpoints", help="comma-list or @file of privileged endpoints (funclevel)")
    ap.add_argument("--massassign", action="store_true")
    ap.add_argument("--profile-url")
    ap.add_argument("--field", help="'k=v' elevated field to inject (massassign)")
    ap.add_argument("--identity-url")
    a = ap.parse_args()
    verify = not a.insecure
    roles = A.load_roles(a.engagement)
    method = a.method.upper()

    if method not in SAFE and not a.allow_mutation:
        print(json.dumps({"ok": False, "error": f"method {method} is state-changing; refused. Authenticated testing is "
                          "READ-ONLY by default. Pass --allow-mutation only with engagement approval "
                          "(scope.yaml mutation_testing: approved) — the mutation-gate hook also enforces this."}))
        sys.exit(3)

    if a.idor:
        if not (a.owner and a.other and a.canary):
            print(json.dumps({"ok": False, "error": "--idor requires --owner, --other, --canary"})); sys.exit(2)
        ev_owner, _ = one(a.engagement, roles, a.owner, a.url, canary=a.canary, verify=verify)
        ev_other, _ = one(a.engagement, roles, a.other, a.url, canary=a.canary, verify=verify)
        ev_anon, _ = one(a.engagement, roles, "anon", a.url, canary=a.canary, verify=verify)
        ev_ctrl, _ = one(a.engagement, roles, a.other, bogus(a.url), canary=a.canary, verify=verify)
        # authz_model boundary: owner vs other must cross a declared boundary to count
        owner_role = A.get_role(roles, a.owner); other_role = A.get_role(roles, a.other)
        same_tenant = owner_role.get("tenant") and owner_role.get("tenant") == other_role.get("tenant")
        reasons = []
        verdict = "no-idor"
        if ev_owner.get("session_valid") is not True or not ev_owner.get("canary_present"):
            verdict = "inconclusive"; reasons.append("canary not present in OWNER response — wrong canary/object ref (canary must be owner-stored data, not the requested id)")
        elif ev_other.get("session_valid") is not True:
            verdict = "inconclusive"; reasons.append("OTHER role session not live (re-login) — cannot test")
        elif ev_anon.get("canary_present"):
            verdict = "public-not-authz-bug"; reasons.append("anonymous request also returns the owner canary — object is PUBLIC by design, not an access-control bug")
        elif ev_other.get("canary_present") and ev_other.get("body_sha256") != ev_ctrl.get("body_sha256"):
            verdict = "idor-confirmed"; reasons.append("OTHER role's response carries OWNER's canary, anon does not, and it differs from the bogus-id control")
            if same_tenant:
                reasons.append("NOTE: owner and other share a declared tenant/authz scope — confirm this crosses an intended boundary before rating (may be legitimate org-shared access)")
        else:
            reasons.append("OTHER role did not receive owner data, or response equals the bogus-id control (coerced-to-self/denied)")
        out = {"ok": True, "mode": "idor", "object": a.url, "verdict": verdict, "reasons": reasons,
               "authz_model": {"owner": owner_role.get("authz_model"), "other": other_role.get("authz_model"),
                               "same_tenant": bool(same_tenant)},
               "matrix": {"owner": ev_owner, "other": ev_other, "anon": ev_anon, "control_bogus": ev_ctrl}}
        print(json.dumps(out, indent=2))
        return

    if a.funclevel:
        # function-level access control: low-priv must NOT reach privileged endpoints (CWE-285)
        if not (a.role and a.endpoints):
            print(json.dumps({"ok": False, "error": "--funclevel requires --role + --endpoints (comma-list or @file)"})); sys.exit(2)
        eps = a.endpoints[1:].splitlines() if a.endpoints.startswith("@") else [e.strip() for e in a.endpoints.split(",") if e.strip()]
        matrix, fails = [], []
        for ep in eps:
            ev, _ = one(a.engagement, roles, a.role, ep, verify=verify)
            matrix.append({"endpoint": ep, "status": ev.get("status"), "session_valid": ev.get("session_valid")})
            if ev.get("status") and 200 <= ev["status"] < 300:
                fails.append(ep)
        print(json.dumps({"ok": True, "mode": "funclevel", "role": a.role, "verdict": "funclevel-broken" if fails else "funclevel-enforced",
                           "endpoints_tested": len(eps), "accessible_as_low_priv": fails,
                           "findings": [{"id": "function-level-access-control", "severity": "high",
                            "detail": f"low-priv role '{a.role}' reached privileged endpoint(s) {fails} with HTTP 2xx — function-level access control is broken (CWE-285); not just object-level (IDOR)"}] if fails else [],
                           "matrix": matrix}, indent=2)); return

    if a.massassign:
        # mass-assignment: inject an elevated field, re-read identity, assert no privilege delta (CWE-915)
        if not (a.role and a.profile_url and a.field and a.identity_url):
            print(json.dumps({"ok": False, "error": "--massassign requires --role + --profile-url + --field 'k=v' + --identity-url"})); sys.exit(2)
        if not a.allow_mutation:
            print(json.dumps({"ok": False, "error": "massassign mutates state; pass --allow-mutation (the mutation-gate hook also enforces mutation_testing: approved)"})); sys.exit(3)
        if "=" not in a.field:
            print(json.dumps({"ok": False, "error": "--field must be 'k=v'"})); sys.exit(2)
        k, v = a.field.split("=", 1)
        ev0, _ = one(a.engagement, roles, a.role, a.identity_url, canary=v, verify=verify)   # baseline
        role_obj, jar, bearer, hdrs = load_session(a.engagement, roles, a.role)
        import urllib.parse as _up
        body = _up.urlencode({k: v}).encode()
        A.request(a.profile_url, "POST", cookiejar=jar, bearer=bearer,
                  headers={**hdrs, "Content-Type": "application/x-www-form-urlencoded"}, data=body, verify=verify)
        ev1, _ = one(a.engagement, roles, a.role, a.identity_url, canary=v, verify=verify)   # after
        escalated = ev1.get("canary_present") and not ev0.get("canary_present")
        print(json.dumps({"ok": True, "mode": "massassign", "role": a.role, "field": a.field, "verdict": "mass-assignment-confirmed" if escalated else "no-delta",
                           "identity_before": ev0.get("body_sha256"), "identity_after": ev1.get("body_sha256"),
                           "elevated_value_now_in_identity": bool(ev1.get("canary_present")),
                           "findings": [{"id": "mass-assignment", "severity": "high",
                            "detail": f"injected '{a.field}' persisted into the identity/profile (privilege delta) — mass-assignment of a privilege-bearing field (CWE-915)"}] if escalated else [],
                           "note": "no-delta may mean the field is ignored OR filtered — re-try alternate field names / JSON body if the surface looks merge-driven"}, indent=2)); return

    if not a.role:
        print(json.dumps({"ok": False, "error": "single mode requires --role (or use --idor)"})); sys.exit(2)
    ev, r = one(a.engagement, roles, a.role, a.url, method=method, canary=a.canary, verify=verify)
    if a.save:
        body = (r["body"] or b"").decode("utf-8", "replace")
        transcript = f"{method} {a.url}\nstatus: {r['status']}\n\n" + body[:8000]
        n = A.write_redacted(a.save, transcript)
        ev["saved"] = a.save; ev["redactions"] = n
    ev["ok"] = True
    print(json.dumps(ev, indent=2))

if __name__ == "__main__":
    main()
