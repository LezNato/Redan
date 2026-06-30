#!/usr/bin/env python
"""finding_schema.py — deterministic validator for an engagement findings.json.

findings.json is the SINGLE SOURCE for report.md/html/pdf, but nothing validated
it — a severity that doesn't match its CVSS band, a count that drifts from the
actual findings, a confirmed finding missing its reproduction, or a bad
disposition/confidence enum would flow straight into the client deliverable.
This is the redact.py-style backstop: deterministic, FATAL on error (nonzero
exit) so the QA gate / reporter can BLOCK.

Checks (errors are fatal; warnings are advisory):
  - structure: findings[] / informational[] / counts{} present
  - each confirmed finding has the required fields (evidence-standard.md)
  - severity is a valid tier; cvss_score is numeric
  - SEVERITY NOT INFLATED ABOVE ITS CVSS BAND (down-rating is allowed — the
    evidence standard says err toward optimism / correct DOWN — so we only flag
    severity *higher* than the band, never lower)
  - counts{} equal the actual tally (findings by severity; info = len(informational))
  - validation_status (if present) is verified|available|unconfirmed
  - REFERENCE INTEGRITY: evidence_index refs point to real finding/lead/info ids (no
    dangling 'F-05' left after a move/downgrade — doctrine §9)
  - COUNT INTEGRITY: counts STATED in the summary prose ('5 leads', '10 informational')
    match the arrays — the recalled-summary drift class the LLM QA gate used to catch
  - reproduction quality (warning): a finding whose reproduction is only 'not performed'
    is likely a version-match LEAD mislabeled as a Finding

Usage: python finding_schema.py <findings.json>
"""
import sys, json, re, os

ID_RE = re.compile(r'\b([FLI]-\d+)\b')      # F-01 / L-04 / I-10 style finding ids
SEV = ["critical", "high", "medium", "low", "info"]
RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# NOTE: 'impact' is a mandatory CONTENT requirement (evidence-standard.md "A finding MUST have"
# item 5) but is embedded in description/verification, not a standalone JSON field. This list
# validates STRUCTURE; the QA-gate's semantic lenses check impact-in-description.
REQUIRED = ["id", "title", "severity", "cvss_vector", "cvss_score", "cwe",
            "location", "description", "reproduction", "evidence", "remediation", "verification"]
VALID_STATUS = {"verified", "available", "unconfirmed"}

def _brace_expand(s):
    """Expand at most one {a,b,c} group (evidence lists like dir/{x,y,z})."""
    m = re.search(r"\{([^{}]+)\}", s)
    if not m:
        return [s]
    pre, post = s[:m.start()], s[m.end():]
    return [pre + o.strip() + post for o in m.group(1).split(",")]

def _evidence_file_tokens(ev_field):
    """Conservatively extract file-like path tokens from an .evidence[] entry.
    Strips trailing descriptions (em/en-dash, ' - '/' -- ', parentheticals), brace-expands
    {a,b}, splits ' / '-lists. Returns ONLY tokens that look like a path (a '.' in the final
    segment OR a '/') and are not URLs — so prose/fragments are never flagged."""
    tokens = set()
    for e in (ev_field or []):
        if not isinstance(e, str):
            continue
        head = re.split(r"\s+[—–]\s+|\s+-{1,2}\s+|\s+\(", e, maxsplit=1)[0]
        for piece in _brace_expand(head):
            for tok in re.split(r"\s*/\s+", piece):
                tok = tok.strip().strip("`'\"")
                if not tok or tok.startswith(("http://", "https://", "//")):
                    continue
                if "." in tok.split("/")[-1] or "/" in tok:
                    tokens.add(tok)
    return tokens

def band_of(c):
    if c is None: return None
    if c >= 9.0: return "critical"
    if c >= 7.0: return "high"
    if c >= 4.0: return "medium"
    if c >= 0.1: return "low"
    return "info"

def validate(d, evidence_root=None):
    errors, warnings = [], []
    for key in ("findings", "informational", "counts"):
        if key not in d:
            errors.append(f"top-level '{key}' missing")
    findings = d.get("findings", []) or []
    info = d.get("informational", []) or []

    tally = {s: 0 for s in SEV}
    for i, f in enumerate(findings):
        fid = f.get("id", f"findings[{i}]")
        for r in REQUIRED:
            v = f.get(r)
            if v is None or (isinstance(v, (str, list)) and len(v) == 0):
                errors.append(f"{fid}: missing/empty required field '{r}'")
        sev = (f.get("severity") or "").lower()
        if sev not in SEV:
            errors.append(f"{fid}: invalid severity '{f.get('severity')}'")
        else:
            tally[sev] += 1
        score = f.get("cvss_score")
        if not isinstance(score, (int, float)):
            errors.append(f"{fid}: cvss_score not numeric ({score!r})")
        elif sev in RANK:
            b = band_of(float(score))
            if b and RANK[sev] > RANK[b]:
                errors.append(f"{fid}: severity '{sev}' is ABOVE the CVSS {score} band "
                              f"('{b}') — inflation. Lower the severity or fix the score "
                              f"(down-rating is allowed; up-rating above the band is not).")
        vs = f.get("validation_status")
        if vs is not None and vs not in VALID_STATUS:
            errors.append(f"{fid}: validation_status '{vs}' not in {sorted(VALID_STATUS)}")
        elif vs is None:
            warnings.append(f"{fid}: no validation_status (recommend verified|available|unconfirmed)")

    counts = d.get("counts", {}) or {}
    for s in ("critical", "high", "medium", "low"):
        if counts.get(s, 0) != tally[s]:
            errors.append(f"counts.{s}={counts.get(s,0)} but findings tally {tally[s]} at '{s}' "
                          f"(exec-summary count drift)")
    if "info" in counts and counts.get("info") != len(info):
        errors.append(f"counts.info={counts.get('info')} but informational[] has {len(info)}")

    for i, x in enumerate(info):
        if not x.get("id") or not x.get("title"):
            warnings.append(f"informational[{i}]: missing id/title")
    leads = d.get("leads", []) or []
    for i, l in enumerate(leads):
        if not l.get("id") or not l.get("title"):
            warnings.append(f"leads[{i}]: missing id/title")

    # --- reference integrity: evidence_index refs must point to real ids (catches the
    #     stale F-05 / F-02-F-03 class — a ref left behind after a move/downgrade, §9) ---
    present = {x.get("id") for k in ("findings", "informational", "leads")
               for x in (d.get(k, []) or []) if x.get("id")}
    for i, x in enumerate(d.get("evidence_index", []) or []):
        for rid in ID_RE.findall(str(x.get("ref", ""))):
            if rid not in present:
                errors.append(f"evidence_index[{i}] ref '{rid}' is a DANGLING reference "
                              f"(no such finding/lead/info id) — stale after a move/downgrade (doctrine §9)")
        # well-formedness: the renderer reads file/contents/ref — a row missing 'file'
        # (e.g. a legacy 'path'/'desc' row) renders as a BLANK appendix row + drops the
        # artifact's embed/caption linkage. Was a human-lens-only catch; now deterministic.
        if isinstance(x, dict) and not x.get("file"):
            legacy = [k for k in ("path", "desc") if k in x]
            hint = f" (has legacy {legacy} key(s) — rename to file/contents)" if legacy else ""
            errors.append(f"evidence_index[{i}] has no 'file' value{hint} — renders as a BLANK "
                          f"appendix row (the renderer reads file/contents/ref)")

    # --- chain provenance: a chain finding's derived_from primitive ids must resolve
    #     (the exploiter emits derived_from:[F-..]; an unresolvable id is a dangling chain link) ---
    for f in findings:
        df = f.get("derived_from")
        if df is None:
            continue
        if not isinstance(df, list):
            errors.append(f"{f.get('id')}: derived_from must be a list of finding/lead ids")
            continue
        for entry in df:
            for rid in (ID_RE.findall(str(entry)) or [str(entry)]):
                if rid not in present:
                    errors.append(f"{f.get('id')}: derived_from references '{rid}' — not a known "
                                  f"finding/lead/info id (dangling chain link, doctrine §9)")

    # --- dangling evidence-path: every .evidence file-token must resolve under evidence/
    #     (converts the LLM "every referenced artifact exists" QA lens into a deterministic
    #     check; brace-expands {a,b}, recurses subdirs, allowlists URLs; prose is never flagged) ---
    if evidence_root and os.path.isdir(evidence_root):
        for section in ("findings", "informational", "leads"):
            for x in d.get(section, []) or []:
                for tok in _evidence_file_tokens(x.get("evidence")):
                    cand = os.path.join(evidence_root, tok.lstrip("./").lstrip("/"))
                    if not (os.path.exists(cand) or
                            os.path.exists(os.path.join(evidence_root, os.path.basename(tok)))):
                        errors.append(f"{x.get('id')}: evidence path '{tok}' does not resolve under "
                                      f"evidence/ (DANGLING-EVIDENCE-PATH — create the artifact or fix the ref)")

    # --- count integrity: counts stated in the summary prose must match the arrays
    #     (finding_schema previously checked counts{} but NOT the recalled summary text — the
    #     '3 leads' vs 5 class the LLM QA gate caught; now deterministic) ---
    summary = d.get("summary", "") or ""
    m = re.search(r'(\d+)\s+leads', summary)
    if m and int(m.group(1)) != len(leads):
        errors.append(f"summary states '{m.group(1)} leads' but leads[] has {len(leads)} "
                      f"(stale recalled count — fix the exec summary, doctrine §9)")
    m = re.search(r'(\d+)\s+informational', summary)
    if m and int(m.group(1)) != len(info):
        errors.append(f"summary states '{m.group(1)} informational' but informational[] has {len(info)}")
    for sev in ("critical", "high", "medium", "low"):
        m = re.search(rf'(\d+)\s+{sev}\b', summary, re.I)
        if m and int(m.group(1)) != tally[sev]:
            warnings.append(f"summary states '{m.group(1)} {sev}' but findings tally {tally[sev]} at '{sev}'")

    # --- reproduction quality: a finding whose reproduction is only 'not performed' is
    #     likely a version-match LEAD mislabeled as a Finding (the Elementor-CVE class) ---
    for f in findings:
        rep = f.get("reproduction")
        rep_txt = " ".join(rep) if isinstance(rep, list) else str(rep or "")
        if re.search(r'not performed', rep_txt, re.I) and not re.search(
                r'attempt|block|reproduc|confirm|returned|HTTP|\b200\b|\b40\d\b|exploit|inject|enumerat|disclos', rep_txt, re.I):
            warnings.append(f"{f.get('id')}: reproduction reads 'not performed' with no demonstrated step — "
                            f"may be a version-match LEAD mislabeled as a Finding (evidence-standard.md)")
    return errors, warnings

def main():
    if len(sys.argv) < 2:
        print("usage: python finding_schema.py <findings.json>"); sys.exit(2)
    try:
        with open(sys.argv[1], encoding="utf-8") as f:
            d = json.load(f)
    except Exception as e:
        print(json.dumps({"file": sys.argv[1], "valid": False, "errors": [f"unreadable/invalid JSON: {e}"]}))
        sys.exit(1)
    errors, warnings = validate(d, os.path.join(os.path.dirname(os.path.abspath(sys.argv[1])), "evidence"))
    print(json.dumps({"file": sys.argv[1], "valid": not errors,
                      "errors": errors, "warnings": warnings}, indent=2))
    sys.exit(1 if errors else 0)

if __name__ == "__main__":
    main()
