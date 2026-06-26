#!/usr/bin/env python
"""_authlib.py — shared core for auth_login.py / auth_request.py.

Centralizes the security-critical bits the red-team flagged:
  - OUT-OF-TREE credential storage (gitignore is inert — not a git repo), under
    $PENTEST_AUTH_HOME or ~/.redan/auth/<engagement>/, perms 0700/0600.
  - Secrets resolved from *_env env vars (preferred) or literal fields; NEVER from
    argv. Only {role,type,authz_model,...} non-secret fields are returned to callers.
  - Real cookie jar (MozillaCookieJar) preserving attributes.
  - Positive session-liveness probe (own identity present, login markers absent).
  - TLS validation ON by default (login POSTs real passwords).
  - Redaction reused from redact.py for any transcript written.
"""
import os, sys, ssl, json, stat, time, base64, urllib.request, urllib.error
from http.cookiejar import MozillaCookieJar

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from redact import redact_text
except Exception:
    def redact_text(s): return s, 0

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

def auth_home(engagement):
    # PENTEST_AUTH_HOME is intentionally named generically ("pentest auth home") — it is a
    # stable public env var, NOT old branding; kept through the Redan rename on purpose.
    base = os.environ.get("PENTEST_AUTH_HOME") or os.path.join(os.path.expanduser("~"), ".redan", "auth")
    d = os.path.join(base, engagement)
    os.makedirs(os.path.join(d, "sessions"), exist_ok=True)
    try: os.chmod(base, 0o700); os.chmod(d, 0o700)
    except Exception: pass
    return d

def _chmod600(path):
    try: os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except Exception: pass

def load_roles(engagement):
    p = os.path.join(auth_home(engagement), "roles.json")
    if not os.path.exists(p):
        raise FileNotFoundError(f"no roles.json at {p} — run /pentest-init or create it (out of tree).")
    # warn (not fail) on loose perms
    try:
        if (os.stat(p).st_mode & 0o077) and os.name == "posix":
            sys.stderr.write(f"[authlib] WARNING: {p} is group/other-accessible; chmod 600.\n")
    except Exception: pass
    with open(p, encoding="utf-8") as f:
        return json.load(f)

def get_role(roles, name):
    for r in roles.get("roles", []):
        if r.get("role") == name:
            return r
    raise KeyError(f"role '{name}' not in roles.json")

def secret(role, kind):
    """kind = 'password' | 'token'. Prefer <kind>_env, else literal. Never argv."""
    env_key = role.get(kind + "_env")
    if env_key:
        v = os.environ.get(env_key)
        if not v:
            raise KeyError(f"env var {env_key} for role {role.get('role')} is unset")
        return v
    if role.get(kind):
        return role[kind]
    raise KeyError(f"no {kind}/{kind}_env for role {role.get('role')}")

def session_path(engagement, role_name):
    return os.path.join(auth_home(engagement), "sessions", role_name + ".cookie")

def token_path(engagement, role_name):
    return os.path.join(auth_home(engagement), "sessions", role_name + ".token.json")

def save_token(engagement, role_name, token):
    """Persist a RUNTIME-ACQUIRED bearer token (the `json` login type) out-of-tree, perms 600.
    The operator-provided `token` type keeps tokens in ENV (never disk); THIS is for tokens the
    tool itself acquires via a JSON/REST login, stored as a session artifact analogous to the
    form-type cookie jar (sessions/<role>.cookie). Cleared by session expiry/rotation."""
    import time as _t
    tp = token_path(engagement, role_name)
    with open(tp, "w", encoding="utf-8") as f:
        json.dump({"token": token, "acquired_at": int(_t.time())}, f)
    _chmod600(tp)
    return tp

def load_token(engagement, role_name):
    tp = token_path(engagement, role_name)
    if not os.path.exists(tp):
        return None
    try:
        return json.load(open(tp, encoding="utf-8")).get("token")
    except Exception:
        return None

def ctx(verify=True):
    if verify:
        return ssl.create_default_context()
    c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
    return c

def request(url, method="GET", cookiejar=None, bearer=None, headers=None, data=None, verify=True, timeout=20):
    """Single HTTP request. Returns dict; never raises on HTTP status, never logs secrets."""
    h = {"User-Agent": UA, "Accept": "*/*"}
    if bearer: h["Authorization"] = "Bearer " + bearer
    if headers: h.update(headers)
    handlers = [urllib.request.HTTPSHandler(context=ctx(verify))]
    if cookiejar is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(cookiejar))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, method=method, headers=h, data=data)
    try:
        r = opener.open(req, timeout=timeout)
        body = r.read(200000)
        return {"status": r.getcode(), "headers": dict(r.headers), "body": body, "final_url": r.geturl(), "error": None}
    except urllib.error.HTTPError as e:
        try: body = e.read(200000)
        except Exception: body = b""
        return {"status": e.code, "headers": dict(e.headers or {}), "body": body, "final_url": url, "error": None}
    except Exception as e:
        return {"status": None, "headers": {}, "body": b"", "final_url": url, "error": str(e)}

def jwt_exp(token):
    """Return unix exp from a JWT without verifying signature, or None."""
    try:
        p = token.split(".")[1]
        p += "=" * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p)).get("exp")
    except Exception:
        return None

def liveness(role, cookiejar=None, bearer=None, verify=True):
    """Positive identity check: identity_marker present AND login markers absent AND
    not redirected to login_url. Returns (valid: bool|None, detail). None = unverifiable
    (no identity_url configured) — callers must fail closed for authz tests."""
    iu = role.get("identity_url")
    marker = role.get("identity_marker")
    if not iu or not marker:
        return None, "no identity_url/identity_marker configured — cannot positively confirm session"
    r = request(iu, "GET", cookiejar=cookiejar, bearer=bearer, verify=verify)
    if r["error"] or r["status"] is None:
        return False, "identity probe failed: " + str(r["error"])
    text = r["body"].decode("utf-8", "replace")
    login_url = role.get("login_url", "")
    if login_url and login_url in (r["final_url"] or ""):
        return False, "redirected to login_url — session not authenticated"
    if marker not in text:
        return False, "identity_marker absent — session not authenticated (likely logged out/expired)"
    for bad in role.get("login_markers_absent", []):
        if bad in text:
            return False, f"login marker present ('{bad}') — session not authenticated"
    return True, "identity confirmed"

def write_redacted(path, text):
    red, n = redact_text(text)
    with open(path, "w", encoding="utf-8") as f:
        f.write(red)
    _chmod600(path)
    return n
