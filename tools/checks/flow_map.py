#!/usr/bin/env python
"""flow_map.py — business-process + expected-authz SKELETON (the oracle black-box logic testing lacks).

Redan has the business-logic PROBE (`flow_probe`) but no upstream artifact that says what the app
INTENDS — so "the server accepted quantity=-1" is only a finding if -1 violates a DOCUMENTED rule
(`pitfalls.md`: accepted-value != bug). This tool builds the OBSERVED skeleton of that intent model
deterministically — multi-step flows, an anonymous access matrix, and candidate invariants — which
the recon/mapper agent then TRANSFORMS into `engagements/<name>/business_process_map.json` (fill
`expected_authz`, fold the candidate invariants into each flow's `invariants`): the oracle the
`logic` / `access-control` lenses test against and the `verifier` judges "is this diff a REAL
violation?" against.

Candidate invariants come at two levels: PARAM-level (a param name -> its rule: price/qty/status/
coupon/ownership) and ENDPOINT-level (an approval step -> separation-of-duties; an audit/immutable
record -> append-only) — the latter reach the SoD/immutability rules no param name encodes.

Discipline it inherits from the kit:
  * NOISE-LOW: params/paths are matched at TOKEN boundaries (snake_case/camelCase split), never as
    substrings — so `discount`/`account_id`/`remember`/`feedback`/`summary` are not misclassified.
  * SOFT-404 CALIBRATED: the anon access matrix is calibrated against known-nonexistent paths; an
    SPA/edge that 200s every path (the kit's #1 false positive) is flagged `catch_all` and its
    "open" rows are down-classed to `soft-404`, NOT surfaced as public-unauth leads.
  * LEAD-ONLY: it asserts NOTHING is a vuln (no disposition). Every row is a LEAD the mapper
    confirms as intent and a tester then tests. `provisional:true` until the mapper annotates.

For AUTHENTICATED coverage the oracle already exists (`roles.json` authz_model/owned_objects); this
fills the black-box / unauthenticated gap. `--cookie` adds a real authed column (anon-vs-authed
contrast = a strong expected-authz signal). RoE-gentle: bounded crawl + a capped anon/authed probe.

Usage: python flow_map.py <base-url> [--depth 2] [--max-pages 60] [--cookie "k=v"]
        [--max-probe 50] [--concurrency N]
"""
import argparse, json, os, re, sys
from urllib.parse import urlparse, urljoin
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import crawler  # noqa: E402  (reuse the same-origin crawler's surface discovery)
from _http import get  # noqa: E402

RANDOM_SEG = "redan-nx-9d3f1a"          # known-nonexistent paths -> the soft-404/catch-all baseline
RANDOM_SEG2 = "redan-nx-4b7e02"

# invariant type -> (whole-token keyword set, the intended rule + the test the logic lens runs).
# Matched at TOKEN boundaries (see _classify), so `count` in "discount" / `fee` in "feedback" do NOT hit.
INV = [
    ("no-client-privilege", {"role", "roles", "isadmin", "admin", "privilege", "privileges",
                             "permission", "permissions", "staff", "accesslevel", "usergroup", "superuser"},
     "a privilege/role field must not be client-settable; add/elevate it on create/update, re-read identity"),
    ("server-authoritative-price", {"price", "amount", "total", "cost", "fee", "fees", "subtotal", "balance", "payable"},
     "price/amount must be server-set; set it client-side on submit and re-read the order total"),
    ("sane-quantity", {"qty", "quantity", "count", "item", "items", "unit", "units", "num", "number"},
     "quantity must be a sane positive integer; try 0 / -1 / a huge value and re-read the effect"),
    ("single-use-code", {"coupon", "promo", "voucher", "discount", "gift", "referral", "rebate", "code"},
     "a discount code should apply once; replay it / stack two and re-read the total"),
    ("no-client-state-jump", {"status", "state", "approved", "verified", "paid", "confirmed",
                              "activated", "enabled", "stage", "phase", "step"},
     "a workflow state must transition server-side; set it directly / skip a step and re-read"),
]
OWN_TOKENS = {"owner", "uid", "customer", "tenant"}                  # bare ownership tokens
OWN_ENTITY = {"user", "account", "order", "object", "item", "product", "profile", "member", "org"}  # entity + id -> ref

# path tokens that mark a route a black-box tester would EXPECT to be access-controlled
SENSITIVE_TOKENS = {"admin", "account", "accounts", "user", "users", "order", "orders", "api", "profile",
                    "settings", "setting", "dashboard", "internal", "manage", "management", "billing",
                    "invoice", "invoices", "payment", "payments", "report", "reports", "export", "config",
                    "me", "owner", "tenant", "private"}

# ENDPOINT-level invariant heuristics (the param classifier can't reach these).
# Matched at TOKEN boundaries (see _toks) so login != log, blog != log, feedback != fee.
# APPROVAL_TOKENS is deliberately TIGHT — only verbs that unambiguously mean "a second party
# formally approves an object someone else created". Broad / self-actor verbs are left OUT on
# purpose because they FP on high-volume routes the path guard can't split: publish/release
# (CMS content), authorize/grant (OAuth self-consent, single-admin grants), endorse/verdict
# (social / media content). verify/confirm/activate are account-lifecycle (you act on your OWN
# resource), never two-party approval — so they simply aren't approval tokens.
APPROVAL_TOKENS = {"approve", "approval", "signoff", "countersign", "ratify"}
# tight audit set; 'trail'/'journal'/'changelog'/'log'/'history' left out (blog/diary/docs-page
# FPs) — a real audit trail is spelled audit-trail / audit_log, already caught by the 'audit' token.
AUDIT_TOKENS = {"audit", "auditlog"}
SOD_TEST = ("two-party control (separation of duties): the approving principal must differ from the "
            "object's creator — create as principal A, then attempt this step as A (self-approval) AND "
            "as a non-approver role; both must be rejected. Drive with auth_request --funclevel (two accounts).")
APPENDONLY_TEST = ("records must be immutable — probe DELETE/PUT/PATCH (+ X-HTTP-Method-Override) via "
                   "forbidden_bypass; every role incl. admin must be denied; re-read to confirm the record "
                   "is unchanged. A successful edit/delete = critical integrity failure (covering tracks).")

FLOW_HINTS = {
    "registration": r"regist|signup|sign-?up|create-?account|join|enrol",
    "authentication": r"login|signin|sign-?in|/auth",
    "password-reset": r"reset|forgot|recover|change-?password",
    "email-verification": r"verify|confirm|activat|validation",
    "checkout": r"cart|checkout|basket|order|payment|/pay|billing|purchase",
    "profile-mgmt": r"profile|/account|settings|preferences",
}
_FLOW = {k: re.compile(v, re.I) for k, v in FLOW_HINTS.items()}
LOGIN_RE = re.compile(r"login|signin|sign-?in|/auth|sso|/session", re.I)
GATED = {401, 403}
_TOKEN = re.compile(r"[a-z0-9]+")


def _toks(name):
    """Lower-case token set of a param/path (snake_case + camelCase split)."""
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name or "")
    return set(_TOKEN.findall(s.lower()))


def _classify(param):
    """(invariant_type, test) for a param name, matched at token boundaries — or (None, None)."""
    t = _toks(param)
    if not t:
        return None, None
    if (OWN_TOKENS & t) or ("id" in t and (OWN_ENTITY & t)):
        return "object-ownership", ("an object ref must be ownership-checked; swap it to another "
                                    "principal's id AS THE LEAST-PRIV identity")
    for typ, keys, test in INV:
        if keys & t:
            return typ, test
    return None, None


def _sensitive(path):
    return bool(SENSITIVE_TOKENS & _toks(path))


def _len_band(a, b, tol=0.05, floor=32):
    return abs(a - b) <= max(floor, int(tol * max(a, b, 1)))


def _access_class(status):
    if status is None:
        return "unreachable"
    if status in GATED:
        return "gated"
    if 300 <= status < 400:
        return "redirect"
    if 200 <= status < 300:
        return "open"
    if status == 404:
        return "absent"
    return f"other-{status}"


def _paths(base, cr):
    """Same-origin path set from the crawl (pages + form actions + JS endpoints + param paths)."""
    host = urlparse(base).netloc
    out = {}
    def add(u):
        full = urljoin(base, u)
        pu = urlparse(full)
        if pu.netloc and pu.netloc != host:
            return
        out.setdefault(pu.path or "/", full)
    for u in cr.get("urls", []):
        add(u)
    for f in cr.get("forms", []):
        add(f.get("action") or base)
    for ep in cr.get("js_endpoints", []):
        add(ep)
    for pp in cr.get("params", []):
        add(pp.get("path") or "/")
    return out


def _flows(base, cr):
    """Group discovered forms + endpoints into named multi-step flows by path hint."""
    steps_by_flow = {}
    def classify(path):
        return [name for name, rx in _FLOW.items() if rx.search(path or "")]
    for f in cr.get("forms", []):
        path = urlparse(urljoin(base, f.get("action") or base)).path or "/"
        for name in classify(path) or classify(" ".join(f.get("inputs", []))):
            steps_by_flow.setdefault(name, []).append(
                {"endpoint": path, "method": f.get("method", "GET"), "params": f.get("inputs", [])[:20]})
    for ep in cr.get("js_endpoints", []):
        path = urlparse(urljoin(base, ep)).path or "/"
        for name in classify(path):
            steps_by_flow.setdefault(name, []).append({"endpoint": path, "method": "?", "params": []})
    flows = []
    for name, steps in steps_by_flow.items():
        seen, uniq = set(), []
        for s in steps:
            k = (s["endpoint"], s["method"])
            if k not in seen:
                seen.add(k); uniq.append(s)
        flows.append({"name": name, "steps": uniq, "invariants": [],
                      "note": "steps observed by crawl (order is best-effort) — the mapper confirms the intended sequence + fills invariants[]"})
    return flows


def _invariants(base, cr):
    seen, out = set(), []
    def consider(path, param):
        typ, test = _classify(param)
        if not typ:
            return
        key = (typ, (param or "").lower())
        if key in seen:
            return
        seen.add(key)
        out.append({"param": param, "location": path, "type": typ, "test": test, "basis": "param"})
    for f in cr.get("forms", []):
        path = urlparse(urljoin(base, f.get("action") or base)).path or "/"
        for name in f.get("inputs", []):
            consider(path, name)
    for pp in cr.get("params", []):
        consider(pp.get("path") or "/", pp.get("param") or "")
    return sorted(out, key=lambda x: (x["type"], x["param"].lower()))


def _endpoint_invariants(base, paths, cr, flows):
    """Endpoint/method-level candidate invariants the param classifier can't reach:
    separation-of-duties (an approval step) and append-only (an audit/immutable record).
    Scans the full discovered path set (audit/approval routes are often plain links, not forms).
    Pure classification over already-crawled data — no new requests."""
    meth = {}
    for f in cr.get("forms", []):
        pp = urlparse(urljoin(base, f.get("action") or base)).path or "/"
        meth.setdefault(pp, f.get("method", "?"))
    flow_eps = {s.get("endpoint") for fl in flows for s in fl.get("steps", [])}
    out, seen = [], set()
    for path in sorted(paths):
        toks = _toks(path)
        segs = [s for s in path.split("/") if s]
        m = meth.get(path, "?")
        # A) separation-of-duties on an approval step. Precision guard: the approval verb must ACT
        # ON A RESOURCE — a multi-segment path (/po/{id}/approve, /approve/{id}, /approveOrder/{id})
        # — or be a step in a discovered flow. A bare single-segment /approve landing page is skipped.
        if (APPROVAL_TOKENS & toks) and (len(segs) > 1 or path in flow_eps) and ("sod", path) not in seen:
            seen.add(("sod", path))
            out.append({"param": None, "location": path, "method": m,
                        "type": "separation-of-duties", "test": SOD_TEST, "basis": "endpoint"})
        # B) append-only on an audit/immutable record (crawls rarely reveal DELETE/PUT, so this flags
        # the endpoint as immutability-critical and hands the mutating-verb probe to forbidden_bypass)
        if (AUDIT_TOKENS & toks) and ("audit", path) not in seen:
            seen.add(("audit", path))
            out.append({"param": None, "location": path, "method": m,
                        "type": "append-only", "test": APPENDONLY_TEST, "basis": "endpoint"})
    return out


def _probe(url, cookie=None):
    r = get(url, timeout=12, allow_redirects=False, headers=({"Cookie": cookie} if cookie else None))
    if r.error:
        return None, b"", None
    return r.status, r.body or b"", r.header("location")


def run(base, depth, max_pages, cookie, max_probe, conc):
    cr = crawler.crawl(base, depth=depth, max_pages=max_pages, cookie=cookie, conc=conc)
    paths = _paths(base, cr)

    # calibrate the soft-404 / SPA catch-all shell (the kit's #1 false positive): if two
    # known-nonexistent paths both 200 with a consistent body length, every "open" is suspect.
    c1s, c1b, _ = _probe(urljoin(base, "/" + RANDOM_SEG))
    c2s, c2b, _ = _probe(urljoin(base, "/" + RANDOM_SEG2))
    catch_all = bool(c1s and 200 <= c1s < 300 and c2s and 200 <= c2s < 300
                     and _len_band(len(c1b), len(c2b)))
    shell_len = len(c1b) if catch_all else None

    matrix = []
    for path in sorted(paths)[:max_probe]:
        status, body, loc = _probe(paths[path])
        cls = _access_class(status)
        if cls == "open" and catch_all and _len_band(len(body), shell_len):
            cls = "soft-404"   # a 200 that matches the catch-all shell is not really "open"
        row = {"path": path, "anon_status": status, "anon_class": cls, "sensitive": _sensitive(path)}
        if cls == "redirect" and loc:
            row["redirect_to"] = loc[:200]
        if cookie:
            a_status, _, _ = _probe(paths[path], cookie=cookie)
            row["authed_status"] = a_status
            row["authed_class"] = _access_class(a_status)
        matrix.append(row)

    flows = _flows(base, cr)
    invs = _invariants(base, cr) + _endpoint_invariants(base, paths, cr, flows)
    invs = sorted(invs, key=lambda x: (x["type"], (x.get("param") or x.get("location") or "").lower()))

    # a pre-seeded expected_authz SCAFFOLD (anon column from what we OBSERVED; user/admin blank for
    # the mapper to FILL) — so the producer shape matches what the consumers read (verifier /
    # auth-tester / pentest-assess key on expected_authz), and the authz half can't silently no-op.
    def _anon_expect(cls):
        return "allow" if cls == "open" else "deny" if cls in ("gated", "redirect") else "?"
    expected_authz = [{"path": m["path"], "anon": _anon_expect(m["anon_class"]), "user": "?", "admin": "?"}
                      for m in matrix if m["sensitive"]]

    # black-box leads to look at first (soft-404 rows are EXCLUDED from public_sensitive by design)
    public_sensitive = [m["path"] for m in matrix if m["sensitive"] and m["anon_class"] == "open"]
    bypass = [m["path"] for m in matrix if m["anon_class"] == "gated"
              or (m["anon_class"] == "redirect" and m["sensitive"])]

    return {
        "tool": "flow_map", "target": base, "ok": True, "provisional": True, "catch_all": catch_all,
        "flows": flows, "access_matrix": matrix, "candidate_invariants": invs,
        "expected_authz": expected_authz,
        "hints": {"public_sensitive_paths": public_sensitive[:20],
                  "gated_paths_to_test_bypass": bypass[:20]},
        "pages_crawled": cr.get("pages_crawled", 0),
        "note": ("OBSERVED SKELETON (deterministic) — the recon/mapper agent TRANSFORMS this into "
                 "engagements/<name>/business_process_map.json: fill `expected_authz` (user/admin columns) "
                 "and fold `candidate_invariants` into each flow's `invariants[]`. That annotated map is the "
                 "ORACLE. Every row is a LEAD: a candidate invariant counts as a finding only when a test "
                 "VIOLATES a DOCUMENTED intent (pitfalls.md: accepted-value != bug); a gated path is a "
                 "forbidden_bypass target; a public sensitive path is a public-unauth lead. "
                 + ("catch_all=TRUE: the edge/SPA 200s every path (soft-404 shell) — the 'open' column is "
                    "unreliable and public_sensitive was suppressed; re-test via the browser channel. "
                    if catch_all else "")
                 + "Authenticated coverage uses roles.json authz_model/owned_objects — this fills the "
                 "black-box/unauthenticated gap. provisional:true until the mapper annotates."),
    }


def main():
    ap = argparse.ArgumentParser(description="Business-process + expected-authz skeleton (the black-box logic oracle)")
    ap.add_argument("base")
    ap.add_argument("--depth", type=int, default=2)
    ap.add_argument("--max-pages", type=int, default=60)
    ap.add_argument("--cookie", help="authed crawl DISCOVERY + a second authed probe per path (adds an "
                                     "authed_status/authed_class column the mapper contrasts vs anon; read-only GET)")
    ap.add_argument("--max-probe", type=int, default=50, help="cap on paths probed for the access matrix (RoE)")
    ap.add_argument("--concurrency", type=int, default=None)
    a = ap.parse_args()
    print(json.dumps(run(a.base, a.depth, a.max_pages, a.cookie, a.max_probe, a.concurrency), indent=2))


if __name__ == "__main__":
    main()
