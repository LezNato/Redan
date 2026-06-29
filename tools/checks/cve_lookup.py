#!/usr/bin/env python
"""cve_lookup.py — deterministic known-vulnerability lookup via OSV.dev (free, no API key)
+ black-box JS-library version fingerprinting.

Closes the "vulnerable components" gap: detect a component +
version, get its real CVEs from an authoritative source — instead of the LLM guessing from a
possibly-stale memory. Per the evidence standard a version->CVE match is a LEAD until
exploitability/reachability is shown.

COVERAGE-GAP HONESTY: OSV.dev does NOT index WordPress plugins (it returns
HTTP 400 'Invalid ecosystem' for ecosystem=WordPress). Without explicit handling, that error is swallowed into
a silent {vulns:[]} that read as 'clean' — suppressing all real WP-plugin CVEs on the tested site. Now:
when the source cannot cover the ecosystem, the result carries coverage_gap:true +
coverage_gap_reason (and a stderr note) so the finder / QA-gate see 'source blind here' instead
of a false clean. WordPress-plugin CVEs must be corroborated via WPScan (token) / NVD / the
vendor advisory (the QA-gate item-4 CVE-corroboration lens does this).

Usage:
  python cve_lookup.py --ecosystem npm --package lodash --version 4.17.10
  python cve_lookup.py --ecosystem WordPress --package example-plugin --version 0.0.0   # -> coverage_gap (OSV has no WP ecosystem)
  python cve_lookup.py --url https://target/          # fingerprint loaded JS libs -> OSV
"""
import sys, os, re, json, ssl, argparse, urllib.request, urllib.error
from urllib.parse import urljoin, urlparse

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
OSV = "https://api.osv.dev/v1/query"

# OSV has no WordPress ecosystem (HTTP 400 'Invalid ecosystem'); flag these explicitly.
WP_ECOSYSTEMS = {"wordpress", "wp", "wp-plugin", "wordpress-plugin"}

WP_GAP_NOTE = ("OSV.dev does NOT index WordPress plugins (HTTP 400 'Invalid ecosystem'). "
               "WordPress-plugin CVEs are NOT visible here. DO NOT read this as 'no CVEs'. "
               "ACTION: run Workflow({name:'plugin_cve_research', args:{plugins:[{slug,name,version},...]}}) "
               "-- a systematic web-research CVE check across NVD/Wordfence/Patchstack/WPScan. "
               "Alternatively: WPScan (token) / NVD / vendor advisory manual check.")


def osv(ecosystem, name, version, timeout=15):
    """Returns {vulns:[{id,osv_id,source,summary,cvss}], source, coverage_gap, coverage_gap_reason?}."""
    body = json.dumps({"package": {"ecosystem": ecosystem, "name": name}, "version": version}).encode()
    req = urllib.request.Request(OSV, data=body, headers={"Content-Type": "application/json"})
    try:
        data = json.load(urllib.request.urlopen(req, timeout=timeout))
    except urllib.error.HTTPError as e:
        try:
            msg = e.read().decode("utf-8", "replace")[:200]
        except Exception:
            msg = str(e)
        return {"vulns": [], "source": "osv", "coverage_gap": True,
                "coverage_gap_reason": f"OSV HTTP {e.code}: {msg} —OSV does not cover this ecosystem; not 'no CVEs'"}
    except Exception as e:
        return {"vulns": [], "source": "osv", "coverage_gap": True,
                "coverage_gap_reason": f"OSV query failed: {e}"}
    out = []
    for v in data.get("vulns", []):
        cvss = next((s.get("score") for s in v.get("severity", []) if s.get("score")), None)
        cve = next((a for a in v.get("aliases", []) if a.startswith("CVE-")), v.get("id"))
        out.append({"id": cve, "osv_id": v.get("id"), "source": "osv",
                    "summary": (v.get("summary") or "")[:180], "cvss": cvss})
    return {"vulns": out, "source": "osv", "coverage_gap": False}


def lookup(ecosystem, name, version, timeout=15):
    """Ecosystem-aware lookup. WP ecosystems are a known coverage gap —flagged, not hidden."""
    eco = (ecosystem or "").strip()
    r = osv(eco, name, version, timeout)
    if eco.lower() in WP_ECOSYSTEMS:
        r["coverage_gap"] = True
        r["coverage_gap_reason"] = WP_GAP_NOTE
    return r


# black-box JS library fingerprints: (npm name, regex over HTML+JS for a version)
LIBS = [
    ("jquery", re.compile(r'jquery[/\-.]?v?(\d+\.\d+\.\d+)', re.I)),
    ("jquery", re.compile(r'jQuery\s+v?(\d+\.\d+\.\d+)', re.I)),
    ("@angular/core", re.compile(r'@angular/core["\s:@/]*?(\d+\.\d+\.\d+)', re.I)),
    ("angular", re.compile(r'angular[.\-/]?v?(\d+\.\d+\.\d+)', re.I)),
    ("bootstrap", re.compile(r'bootstrap[@/\-.]v?(\d+\.\d+\.\d+)', re.I)),
    ("lodash", re.compile(r'lodash[@/\-.](\d+\.\d+\.\d+)', re.I)),
    ("moment", re.compile(r'moment[@/\-.](\d+\.\d+\.\d+)', re.I)),
    ("axios", re.compile(r'axios[@/\-.](\d+\.\d+\.\d+)', re.I)),
    ("vue", re.compile(r'vue[@/\-.]v?(\d+\.\d+\.\d+)', re.I)),
    ("d3", re.compile(r'\bd3[@/\-.]v?(\d+\.\d+\.\d+)', re.I)),
]

def fetch(url, timeout=20):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    try:
        return urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA}),
                                      timeout=timeout, context=ctx).read().decode("utf-8", "replace")
    except Exception:
        return ""

def fingerprint(url):
    html = fetch(url)
    blob = html
    host = urlparse(url).netloc
    for s in re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, re.I)[:10]:
        full = urljoin(url, s)
        if urlparse(full).netloc == host:
            blob += "\n" + fetch(full)
    found = {}
    for name, pat in LIBS:
        m = pat.search(blob)
        if m:
            found.setdefault(name, m.group(1))
    comps, findings = [], []
    for name, ver in found.items():
        r = osv("npm", name, ver)
        n = len(r.get("vulns", []))
        comps.append({"component": name, "version": ver, "ecosystem": "npm",
                      "known_vulns": n, "source": "osv", "coverage_gap": r.get("coverage_gap", False),
                      "vulns": r["vulns"]})
        if n:
            findings.append({"id": "vulnerable-component", "severity": "medium",
                             "cve": ",".join(v["id"] for v in r["vulns"][:6]),
                             "detail": f"{name} {ver} —{n} known vuln(s) (OSV): "
                                       + ", ".join(v["id"] for v in r["vulns"][:6])})
    note = "version->CVE is a LEAD until exploitability/reachability is confirmed (pitfalls.md)"
    return {"target": url, "ok": True, "components": comps, "findings": findings, "note": note}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("url", nargs="?", help="page URL to fingerprint (alias of --url; --url takes precedence if both)")
    ap.add_argument("--url", dest="url_opt"); ap.add_argument("--ecosystem"); ap.add_argument("--package"); ap.add_argument("--version")
    a = ap.parse_args()
    target = a.url_opt or a.url
    if target:
        print(json.dumps(fingerprint(target), indent=2))
    elif a.ecosystem and a.package and a.version:
        r = lookup(a.ecosystem, a.package, a.version)
        out = {"ecosystem": a.ecosystem, "package": a.package, "version": a.version, **r}
        if r.get("coverage_gap"):
            print(f"[coverage_gap] {r.get('coverage_gap_reason','')}", file=sys.stderr)
        print(json.dumps(out, indent=2))
    else:
        print("usage: cve_lookup.py <url> | --url <page> | --ecosystem E --package P --version V"); sys.exit(2)
