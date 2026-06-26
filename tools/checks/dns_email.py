#!/usr/bin/env python
"""dns_email.py — deterministic DNS + email-security (SPF/DMARC/DKIM) check.

Uses the system `nslookup` (no Python DNS deps). Reports A/AAAA/NS/MX, the SPF
record, the DMARC policy, and which common DKIM selectors resolve — flagging the
classic email-spoofing gaps (no DMARC / p=none, missing/!-all SPF). Emits JSON.

Usage: python dns_email.py <domain>
"""
import sys, os, json, re, ssl, subprocess, urllib.request, urllib.parse, argparse
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _concurrency import workers

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
DKIM_SELECTORS = ["selector1", "selector2", "default", "google", "mail", "k1", "dkim", "s1", "s2"]

def nslookup(name, rtype=None, timeout=15):
    cmd = ["nslookup"] + (["-type=" + rtype] if rtype else []) + [name]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""

def doh(name, rtype, timeout=10):
    """DNS-over-HTTPS via Google's no-key resolver — for record types Windows nslookup can't
    parse (CAA=257, DNSKEY=48). Returns the Answer list (each {name,type,TTL,data})."""
    url = "https://dns.google/resolve?name=" + urllib.parse.quote(name) + "&type=" + rtype
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA}),
                                    timeout=timeout) as r:
            return json.load(r).get("Answer") or []
    except Exception:
        return []

def addrs(domain):
    out = nslookup(domain)
    # drop the resolver's own "Address:" line (appears before "Name:")
    body = out.split("Name:", 1)[-1] if "Name:" in out else out
    return sorted(set(re.findall(r"Address(?:es)?:\s*([0-9a-fA-F:.]+)", body)))

def records(domain, rtype, pattern):
    return sorted(set(re.findall(pattern, nslookup(domain, rtype), re.I)))

def txt(domain):
    raw = nslookup(domain, "TXT")
    return re.findall(r'"([^"]*)"', raw)

def check(domain):
    # all lookups are independent nslookup calls -> run them concurrently (core-scaled)
    with ThreadPoolExecutor(max_workers=workers(cap=16)) as ex:
        f_a = ex.submit(addrs, domain)
        f_ns = ex.submit(records, domain, "NS", r"nameserver\s*=\s*([^\s]+)")
        f_mx = ex.submit(records, domain, "MX", r"mail exchanger\s*=\s*([^\s]+)")
        f_txt = ex.submit(txt, domain)
        f_dmarc = ex.submit(txt, "_dmarc." + domain)
        f_dkim = {s: ex.submit(txt, f"{s}._domainkey.{domain}") for s in DKIM_SELECTORS}
        f_caa = ex.submit(doh, domain, "CAA")
        f_dnskey = ex.submit(doh, domain, "DNSKEY")
        a = f_a.result(); ns = f_ns.result(); mx = f_mx.result()
        caa = [x.get("data", "") for x in f_caa.result() if x.get("type") == 257]
        dnssec_signed = any(x.get("type") == 48 for x in f_dnskey.result())
        spf = next((t for t in f_txt.result() if t.lower().startswith("v=spf1")), None)
        dmarc_txt = next((t for t in f_dmarc.result() if t.lower().startswith("v=dmarc1")), None)
        dkim = [s for s in DKIM_SELECTORS
                if any(x.lower().startswith("v=dkim1") or "p=" in x.lower() for x in f_dkim[s].result())]
    dmarc_policy = None
    if dmarc_txt:
        m = re.search(r"\bp=(\w+)", dmarc_txt)
        dmarc_policy = m.group(1).lower() if m else None
    findings = []
    if not dmarc_txt:
        findings.append({"id": "dmarc-missing", "severity": "medium",
                         "detail": "no DMARC record — domain is spoofable"})
    elif dmarc_policy == "none":
        findings.append({"id": "dmarc-p-none", "severity": "low",
                         "detail": "DMARC p=none — monitoring only, no enforcement"})
    if not spf:
        findings.append({"id": "spf-missing", "severity": "medium", "detail": "no SPF record"})
    elif not re.search(r"[~\-]all\b", spf):
        findings.append({"id": "spf-weak", "severity": "low",
                         "detail": "SPF does not end in -all/~all"})
    if not caa:
        findings.append({"id": "caa-missing", "severity": "low",
                         "detail": "no CAA record — any CA may issue certificates for this domain (defense-in-depth)"})
    if not dnssec_signed:
        findings.append({"id": "dnssec-unsigned", "severity": "low",
                         "detail": "zone is unsigned (no DNSKEY) — no DNS-response forgery protection (defense-in-depth)"})
    return {"target": domain, "ok": True, "a": a, "ns": ns, "mx": mx,
            "spf": spf, "dmarc": {"raw": dmarc_txt, "policy": dmarc_policy},
            "dkim_selectors_found": dkim,
            "dns_posture": {"caa": caa, "dnssec_signed": dnssec_signed},
            "findings": findings}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Deterministic DNS + email-security (SPF/DMARC/DKIM/CAA/DNSSEC) check.")
    ap.add_argument("domain", help="target domain")
    args = ap.parse_args()
    print(json.dumps(check(args.domain), indent=2))
