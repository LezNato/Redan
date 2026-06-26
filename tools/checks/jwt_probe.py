#!/usr/bin/env python
"""jwt_probe.py — JWT attack-surface ANALYZER (stdlib only; no exploitation).

Decodes a captured JWT (from --token, --header "Authorization: Bearer ...", or --file <req>)
and flags the common JWT attack CLASSES — alg:none susceptibility, RS->HS key-confusion
surface, kid injection markers, expired/imminent-expiry, and sensitive claims (role/admin/
scope) — WITHOUT forging or replaying (that's the verifier's job against the endpoint,
operator-gated). A lead generator, not an exploit.

Usage: python jwt_probe.py --token <jwt>
       python jwt_probe.py --header "Authorization: Bearer <jwt>"
       python jwt_probe.py --file <captured-request.txt>     # greps for a JWT-shaped string
"""
import sys, json, base64, argparse, re, time

JWT_RE = re.compile(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b')

def _b64dec(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def decode(tok):
    parts = tok.split(".")
    if len(parts) < 2:
        return None, {"_decode_error": "not a 3-part JWT"}
    try:
        h = json.loads(_b64dec(parts[0])); p = json.loads(_b64dec(parts[1]))
        return h, p
    except Exception as e:
        return None, {"_decode_error": str(e)}

def analyze(tok):
    h, p = decode(tok)
    if h is None:
        return {"target": "jwt:(undecodable)", "ok": False, "error": "not a decodable JWT: " + p.get("_decode_error", ""), "findings": []}
    alg = (h.get("alg") or "").lower()
    findings = []
    if alg in ("none", ""):
        findings.append({"id": "jwt-alg-none", "severity": "high",
                         "detail": "alg is 'none'/empty — the signature may be skippable. Forge a token with alg:{none,} + empty sig and replay against the endpoint to confirm (CWE-347)"})
    kid = str(h.get("kid", ""))
    if alg.startswith("hs") and (h.get("jku") or h.get("jwk") or ("-----BEGIN" in kid) or kid.startswith(("http", "../")) or "'" in kid or '"' in kid):
        findings.append({"id": "jwt-kid-injection-surface", "severity": "high",
                         "detail": "HS alg with a suspicious kid/jku/jwk header — test kid path-traversal/SQLi/JWK-injection/jku trust (CWE-347)"})
    if alg.startswith(("rs", "es", "ps")):
        findings.append({"id": "jwt-rsa-key-confusion-surface", "severity": "medium",
                         "detail": "asymmetric alg — test whether the server accepts HS256 signed with the RSA PUBLIC key as the HMAC secret (the classic RS->HS confusion). Needs the JWKS/public key + the endpoint."})
    elif alg.startswith("hs"):
        findings.append({"id": "jwt-hs256-weak-secret-surface", "severity": "low",
                         "detail": "HS alg — test for a weak/low-entropy signing secret (offline crack via hashcat -m 16500); if cracked, full forgery"})
    exp = p.get("exp")
    if isinstance(exp, (int, float)):
        if exp < time.time():
            findings.append({"id": "jwt-expired", "severity": "info",
                             "detail": f"token exp is in the past (expired ~{int((time.time()-exp)/86400)}d ago)"})
        elif exp - time.time() < 3600:
            findings.append({"id": "jwt-imminent-expiry", "severity": "info",
                             "detail": f"token expires in <1h ({int(exp-time.time())}s)"})
    sensitive = {k: p[k] for k in p if k.lower() in ("role", "roles", "isadmin", "admin", "scope", "user", "userid", "email", "auth", "tenant")}
    if sensitive:
        findings.append({"id": "jwt-sensitive-claims", "severity": "info",
                         "detail": "token carries privilege-bearing claims — tampering these (with a cracked/none/confused key) is the priv-esc path", "claims": list(sensitive)})
    return {"target": "jwt:" + str(h.get("kid") or p.get("iss") or alg or "token"), "ok": True, "alg": alg or "(none)", "header": h, "claims": p, "exp_unix": exp,
            "sensitive_claims": sensitive, "findings": findings,
            "note": "ANALYZER only — confirming alg:none forgery / key confusion / claim-tamper needs a replay against the endpoint (operator-gated). A LEAD, not an exploit."}

def extract(args):
    if args.token:
        return args.token
    if args.header:
        m = re.search(r"Bearer\s+(.+)", args.header, re.I)
        return m.group(1).strip() if m else args.header.strip()
    if args.file:
        try:
            txt = open(args.file, encoding="utf-8", errors="ignore").read()
            m = JWT_RE.search(txt)
            return m.group(0) if m else None
        except Exception:
            return None
    return None

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="JWT attack-surface analyzer")
    ap.add_argument("--token"); ap.add_argument("--header"); ap.add_argument("--file")
    a = ap.parse_args()
    tok = extract(a)
    if not tok:
        print("usage: jwt_probe.py --token <jwt> | --header 'Authorization: Bearer <jwt>' | --file <req.txt>"); sys.exit(2)
    print(json.dumps(analyze(tok), indent=2))
