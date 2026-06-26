#!/usr/bin/env python
"""auth_login.py — acquire an authenticated session per role (out-of-tree).

Reads roles from $PENTEST_AUTH_HOME/<engagement>/roles.json (NOT the repo tree).
Secrets come from *_env env vars or literal fields — NEVER argv. Prints only
status/identity/artifact path; NEVER prints credentials.

Types:
  form          GET login (TLS VALIDATED) -> detect form+password -> extract CSRF
                (hidden input / meta / XSRF cookie->header) -> POST creds with a
                real cookie jar -> confirm success via the LIVENESS probe (own
                identity present, not the login page). SPA/no-form -> needs_browser_login.
  token         take Bearer/JWT from *_env; if JWT, refuse if expired.
  storage_state operator-supplied Playwright storageState.json (for SPA/SSO/MFA
                captured via a real manual login) — validated + referenced.

Usage: python auth_login.py --engagement <slug> [--role <name>] [--insecure]
"""
import sys, os, re, json, argparse, urllib.parse, time
from http.cookiejar import MozillaCookieJar
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _authlib as A

CSRF_NAMES = re.compile(r'(csrfmiddlewaretoken|authenticity_token|__RequestVerificationToken|csrf[_-]?token|_csrf|_token|xsrf|nonce)', re.I)

def engagement_from_scope():
    root = os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd())
    try:
        for line in open(os.path.join(root, "scope.yaml"), encoding="utf-8"):
            m = re.match(r'\s*name\s*:\s*"?([^"\n#]+)', line)
            if m: return m.group(1).strip()
    except Exception: pass
    return None

def extract_csrf(html, headers):
    # hidden inputs whose name looks like a csrf token
    for m in re.finditer(r'<input[^>]+>', html, re.I):
        tag = m.group(0)
        nm = re.search(r'name=["\']([^"\']+)["\']', tag, re.I)
        val = re.search(r'value=["\']([^"\']*)["\']', tag, re.I)
        if nm and val and CSRF_NAMES.search(nm.group(1)):
            return ("field", nm.group(1), val.group(1))
    # meta tag
    m = re.search(r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']', html, re.I)
    if m:
        return ("meta", "csrf-token", m.group(1))
    # XSRF cookie -> echo as header
    sc = headers.get("Set-Cookie", "") if headers else ""
    m = re.search(r'(XSRF-TOKEN|_csrf)=([^;]+)', sc, re.I)
    if m:
        return ("cookie", m.group(1), urllib.parse.unquote(m.group(2)))
    return (None, None, None)

def login_form(role, verify):
    login_url = role["login_url"]
    g = A.request(login_url, "GET", cookiejar=role["_jar"], verify=verify)
    if g["error"]:
        return {"ok": False, "detail": "GET login_url failed: " + g["error"]}
    html = g["body"].decode("utf-8", "replace")
    if "<form" not in html.lower() or not re.search(r'type=["\']?password', html, re.I):
        return {"ok": False, "needs_browser_login": True,
                "detail": "no <form>/password field in GET HTML — JS/SPA login; supply type:storage_state (manual login export) or use the browser path"}
    kind, cname, cval = extract_csrf(html, g["headers"])
    uf = role.get("username_field", "username")
    pf = role.get("password_field", "password")
    data = {uf: role["username"], pf: A.secret(role, "password")}
    data.update(role.get("form_fields", {}))
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if kind in ("field", "meta"): data[cname] = cval
    if kind in ("meta", "cookie"): headers["X-CSRF-Token"] = cval; headers["X-XSRF-TOKEN"] = cval
    body = urllib.parse.urlencode(data).encode()
    p = A.request(login_url, "POST", cookiejar=role["_jar"], headers=headers, data=body, verify=verify)
    if p["error"]:
        return {"ok": False, "detail": "POST login failed: " + p["error"]}
    valid, detail = A.liveness(role, cookiejar=role["_jar"], verify=verify)
    return {"ok": bool(valid), "session_valid": valid, "detail": detail, "csrf": kind or "none"}

def login_json(role, engagement, verify):
    """JSON/REST login: POST {user,pass} as JSON -> extract bearer token via token_path
    (dot-path, default 'token') -> liveness -> persist as a session artifact. Handles the
    SPA/REST-login case the form type can't (most modern apps)."""
    login_url = role["login_url"]
    body = json.dumps({role.get("username_field", "email"): role["username"],
                       role.get("password_field", "password"): A.secret(role, "password")}).encode()
    r = A.request(login_url, "POST",
                  headers={"Content-Type": "application/json", "Accept": "application/json"},
                  data=body, verify=verify)
    if r["error"] or r["status"] is None:
        return {"ok": False, "detail": "JSON login request failed: " + str(r["error"])}
    if r["status"] >= 400:
        return {"ok": False, "detail": f"login rejected (HTTP {r['status']}) — bad credentials or wrong flow"}
    try:
        resp = json.loads(r["body"].decode("utf-8", "replace"))
    except Exception:
        return {"ok": False, "detail": "login response is not JSON"}
    cur = resp
    for part in role.get("token_path", "token").split("."):
        cur = cur.get(part) if isinstance(cur, dict) else None
    if not cur:
        return {"ok": False, "detail": f"token_path '{role.get('token_path','token')}' not found in login response"}
    valid, detail = A.liveness(role, bearer=cur, verify=verify)
    out = {"ok": valid is not False, "session_valid": valid, "detail": detail}
    if valid is not False:
        A.save_token(engagement, role["role"], cur)
        out["artifact"] = A.token_path(engagement, role["role"])
        out["note"] = "json-acquired bearer token stored out-of-tree (600); auth_request reuses it for the session"
    return out

def acquire(role, engagement, verify):
    rtype = role.get("type", "form")
    out = {"role": role.get("role"), "type": rtype}
    if rtype == "form":
        jar = MozillaCookieJar()
        role["_jar"] = jar
        res = login_form(role, verify)
        out.update(res)
        if res.get("ok"):
            sp = A.session_path(engagement, role["role"])
            jar.save(sp, ignore_discard=True, ignore_expires=True)
            A._chmod600(sp)
            out["artifact"] = sp
    elif rtype == "json":
        out.update(login_json(role, engagement, verify))
    elif rtype == "token":
        tok = A.secret(role, "token")
        exp = A.jwt_exp(tok)
        if exp and exp < time.time():
            out.update({"ok": False, "detail": "token expired (JWT exp in the past) — re-mint"})
        else:
            tp = A.token_path(engagement, role["role"])
            with open(tp, "w", encoding="utf-8") as f:
                json.dump({"acquired_at": int(time.time()), "exp": exp}, f)  # token itself stays in env, not on disk
            A._chmod600(tp)
            valid, detail = A.liveness(role, bearer=tok, verify=verify)
            out.update({"ok": valid is not False, "session_valid": valid, "detail": detail, "artifact": tp,
                        "note": "token read from env at use-time; not persisted to disk"})
    elif rtype == "storage_state":
        ss = role.get("storage_state")
        if ss and os.path.exists(ss):
            out.update({"ok": True, "artifact": ss, "detail": "operator storageState referenced (browser/agent path)"})
        else:
            out.update({"ok": False, "needs_browser_login": True,
                        "detail": "storage_state path missing — capture via a real manual login (Playwright storageState export)"})
    else:
        out.update({"ok": False, "detail": f"unknown role type {rtype}"})
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--engagement")
    ap.add_argument("--role")
    ap.add_argument("--insecure", action="store_true", help="disable TLS validation (NOT for real credential POSTs)")
    a = ap.parse_args()
    eng = a.engagement or engagement_from_scope()
    if not eng:
        print(json.dumps({"ok": False, "error": "no --engagement and none in scope.yaml"})); sys.exit(2)
    roles = A.load_roles(eng)
    verify = not a.insecure
    targets = [get for get in roles.get("roles", []) if (not a.role or get.get("role") == a.role)]
    out = [acquire(r, eng, verify) for r in targets]
    print(json.dumps(out if len(out) != 1 else out[0], indent=2))

if __name__ == "__main__":
    main()
