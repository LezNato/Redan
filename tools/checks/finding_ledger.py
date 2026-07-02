#!/usr/bin/env python
"""finding_ledger.py — cross-engagement finding lifecycle + retest (stdlib only).

Turns one-shot assessments into a security PROGRAM: assigns each finding a STABLE
`finding_uid` (a fingerprint that survives re-runs and renaming), tracks its status
over time (open -> fixed -> regressed), and produces a retest DELTA (fixed / still-open
/ new / regressed) for the report.

A finding's IDENTITY is its (target, CWE, normalized-location) — NOT its title or
severity (those drift between runs). The location is normalized so ids are templated
out (`GET /api/orders/1002` -> `/api/orders/{id}`); the same access-control bug at the
same endpoint is then recognized across engagements regardless of which object id was
used to prove it, or which local F-NN it was assigned.

Modes:
  record <findings.json> --engagement <name> --date <YYYY-MM-DD>   upsert findings (status=open)
  retest <findings.json> --engagement <name> --date <YYYY-MM-DD>   diff vs the OPEN ledger -> delta
  uid    --target <t> --cwe <CWE-NN> --location <loc>              print the finding_uid for one finding
  status [--target <t>]                                            show the ledger (open/fixed/regressed)

Ledger path: --ledger <path> (default engagements/_ledger.json — gitignored; holds
real cross-engagement finding history). JSON output to stdout for the reporter to fold
into a "Retest / Delta" section.
"""
import argparse, hashlib, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
DEFAULT_LEDGER = os.path.join(REPO, "engagements", "_ledger.json")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def normalize_location(loc):
    """Canonicalize a finding location so the SAME sink matches across runs:
    drop a method prefix + scheme/host + query/fragment, and template id-like path
    segments (numeric / UUID / long-hex) to {id}."""
    s = (loc or "").strip().lower()
    s = re.sub(r"^[a-z]+\s+", "", s)            # "get /x" -> "/x"
    s = re.sub(r"^https?://[^/]+", "", s)        # strip scheme://host
    s = s.split("?", 1)[0].split("#", 1)[0].split(";", 1)[0]  # drop query/fragment/params
    segs = []
    for seg in s.split("/"):
        if not seg:
            segs.append(seg); continue
        if _UUID.fullmatch(seg) or re.fullmatch(r"\d+", seg) or re.fullmatch(r"[0-9a-f]{12,}", seg):
            segs.append("{id}")
        else:
            segs.append(seg)
    return "/".join(segs) or "/"


def finding_uid(target, cwe, location):
    key = f"{(target or '').strip().lower()}|{(cwe or '').strip().upper()}|{normalize_location(location)}"
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]


def load_ledger(path):
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {"findings": {}}


def save_ledger(path, led):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(led, f, indent=2, ensure_ascii=False)


def findings_of(fj):
    with open(fj, encoding="utf-8") as f:
        d = json.load(f)
    target = (d.get("engagement", {}) or {}).get("target", "")
    out = []
    for f in d.get("findings", []) or []:
        out.append({"uid": finding_uid(target, f.get("cwe"), f.get("location")),
                    "target": target, "cwe": f.get("cwe"), "location": f.get("location"),
                    "title": f.get("title"), "severity": f.get("severity"), "local_id": f.get("id")})
    return target, out


def _new_entry(f, date, engagement, status="open"):
    return {"uid": f["uid"], "target": f["target"], "cwe": f["cwe"], "location": f["location"],
            "title": f["title"], "severity": f["severity"], "status": status,
            "first_seen": date, "last_seen": date,
            "occurrences": [{"engagement": engagement, "date": date,
                             "severity": f["severity"], "local_id": f["local_id"]}]}


def _touch(e, f, date, engagement):
    e["last_seen"] = date; e["title"] = f["title"]; e["severity"] = f["severity"]
    e["occurrences"].append({"engagement": engagement, "date": date,
                             "severity": f["severity"], "local_id": f["local_id"]})


def cmd_record(args):
    target, fs = findings_of(args.findings)
    led = load_ledger(args.ledger)
    new, recurring, regressed = [], [], []
    for f in fs:
        e = led["findings"].get(f["uid"])
        if e is None:
            led["findings"][f["uid"]] = _new_entry(f, args.date, args.engagement)
            new.append(f["uid"])
        else:
            if e["status"] == "fixed":
                e["status"] = "regressed"; regressed.append(f["uid"])
            else:
                e["status"] = "open"; recurring.append(f["uid"])
            _touch(e, f, args.date, args.engagement)
    save_ledger(args.ledger, led)
    return {"mode": "record", "target": target, "engagement": args.engagement,
            "recorded": len(fs), "new": len(new), "recurring": len(recurring), "regressed": len(regressed)}


def cmd_retest(args):
    target, fs = findings_of(args.findings)
    led = load_ledger(args.ledger)
    cur = {f["uid"]: f for f in fs}
    prior_open = {u for u, e in led["findings"].items()
                  if e.get("target") == target and e["status"] in ("open", "regressed")}
    fixed, still_open, regressed, new = [], [], [], []
    # prior-open findings absent from the new run = presumed FIXED; present = still open
    for u in sorted(prior_open):   # deterministic order (prior_open is a set) so the delta lists are byte-stable
        e = led["findings"][u]
        if u in cur:
            _touch(e, cur[u], args.date, args.engagement); e["status"] = "open"; still_open.append(u)
        else:
            e["status"] = "fixed"; e["fixed_date"] = args.date; fixed.append(u)
    # findings in the new run not previously open
    for u, f in cur.items():
        if u in prior_open:
            continue
        e = led["findings"].get(u)
        if e is None:
            led["findings"][u] = _new_entry(f, args.date, args.engagement); new.append(u)
        elif e["status"] == "fixed":
            e["status"] = "regressed"; _touch(e, f, args.date, args.engagement); regressed.append(u)
    save_ledger(args.ledger, led)

    def brief(uids):
        return [{"uid": u, **{k: led["findings"][u].get(k) for k in ("title", "severity", "location", "cwe", "first_seen")}}
                for u in uids]
    delta = {"mode": "retest", "target": target, "engagement": args.engagement, "date": args.date,
             "summary": {"fixed": len(fixed), "still_open": len(still_open), "regressed": len(regressed), "new": len(new)},
             "fixed": brief(fixed), "still_open": brief(still_open), "regressed": brief(regressed), "new": brief(new)}
    # optionally fold the delta into a findings.json so render_report renders a Retest section
    into = args.into or (args.findings if args.write_into else None)
    if into:
        with open(into, encoding="utf-8") as f:
            fd = json.load(f)
        fd["retest"] = {k: delta[k] for k in ("date", "summary", "fixed", "still_open", "regressed", "new")}
        with open(into, "w", encoding="utf-8") as f:
            json.dump(fd, f, indent=2, ensure_ascii=False)
        delta["wrote_into"] = into
    return delta


def cmd_uid(args):
    return {"mode": "uid", "target": args.target, "cwe": args.cwe, "location": args.location,
            "normalized_location": normalize_location(args.location),
            "finding_uid": finding_uid(args.target, args.cwe, args.location)}


def cmd_status(args):
    led = load_ledger(args.ledger)
    items = [e for e in led["findings"].values() if not args.target or e.get("target") == args.target]
    by = {}
    for e in items:
        by.setdefault(e["status"], []).append(
            {"uid": e["uid"], "title": e.get("title"), "severity": e.get("severity"),
             "location": e.get("location"), "first_seen": e.get("first_seen"), "last_seen": e.get("last_seen"),
             "seen_count": len(e.get("occurrences", []))})
    return {"mode": "status", "target": args.target, "total": len(items),
            "counts": {k: len(v) for k, v in by.items()}, "by_status": by}


def main():
    ap = argparse.ArgumentParser(description="cross-engagement finding lifecycle + retest")
    ap.add_argument("mode", choices=["record", "retest", "uid", "status"])
    ap.add_argument("findings", nargs="?", help="path to a findings.json (record/retest)")
    ap.add_argument("--engagement", default="", help="engagement name (record/retest)")
    ap.add_argument("--date", default="", help="YYYY-MM-DD of this run (record/retest)")
    ap.add_argument("--ledger", default=DEFAULT_LEDGER, help=f"ledger path (default {DEFAULT_LEDGER})")
    ap.add_argument("--target", default="", help="filter by target (status) / target for uid")
    ap.add_argument("--cwe", default="", help="CWE id (uid mode)")
    ap.add_argument("--location", default="", help="finding location (uid mode)")
    ap.add_argument("--into", default="", help="retest: also write the delta into this findings.json's 'retest' key (for render_report)")
    ap.add_argument("--write-into", action="store_true", help="retest: write the delta back into the input findings.json")
    a = ap.parse_args()
    if a.mode in ("record", "retest") and not (a.findings and a.date):
        print(json.dumps({"error": f"{a.mode} needs <findings.json> and --date"})); sys.exit(2)
    out = {"record": cmd_record, "retest": cmd_retest, "uid": cmd_uid, "status": cmd_status}[a.mode](a)
    print(json.dumps(out, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
