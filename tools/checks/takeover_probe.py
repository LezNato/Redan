#!/usr/bin/env python
"""takeover_probe.py — subdomain-takeover detector (stdlib only).

For each subdomain (args or a recon list), resolve the CNAME chain, fetch the body, and match
against a fingerprint DB of deprovisioned-resource signatures (S3 NoSuchBucket, Heroku "No such app",
GitHub Pages 404, Azure/CloudFront/Blob, Vercel, S3-Website, etc.). A match = the dangling resource
is CLAIMABLE (the operator must confirm claim-ability within RoE — pitfalls.md). stdlib.

Usage: python takeover_probe.py <subdomain> [<subdomain> ...]   |   --file <subdomains.txt>
"""
import sys, json, socket, ssl, re, argparse, urllib.request, urllib.error

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
_CTX = ssl.create_default_context(); _CTX.check_hostname = False; _CTX.verify_mode = ssl.CERT_NONE

# (service, CNAME-suffix-hint, response-body fingerprint) — body fingerprints are the deprovisioned signature
FINGERPRINTS = [
    ("Amazon S3 bucket", [".s3.amazonaws.com", ".s3-website"], [r"NoSuchBucket", r"The specified bucket does not exist"]),
    ("GitHub Pages", ["github.io", ".github.io"], [r"There isn't a GitHub Pages site here", r"Forbidden"]),
    ("Heroku", ["herokuapp.com", "heroku.com"], [r"No such app", r"There's nothing here"]),
    ("Azure (cloudapp/azureedge/azurewebsites)", ["cloudapp.net", "azureedge.net", "azurewebsites.net", "blob.core.windows.net"], [r"404 Web Site not found", r"The resource you are looking for has been removed", r"Repository not found"]),
    ("Vercel / Now", ["vercel.app", "now.sh"], [r"The deployment could not be found", r"NOT_FOUND"]),
    ("AWS CloudFront", ["cloudfront.net"], [r"Bad request", r"ERROR: The request could not be satisfied"]),
    ("Fastly", ["fastly.net"], [r"Fastly error: unknown domain", r"No such app"]),
    ("Pantheon", ["pantheonsite.io"], [r"The gods are wise", r"404 error unknown site"]),
    ("Surge.sh", ["surge.sh"], [r"project not found"]),
    ("Tumblr", ["tumblr.com"], [r"Whatever you were looking for doesn't currently exist at this address"]),
    ("Shopify", ["myshopify.com"], [r"Sorry, this shop is currently unavailable"]),
    ("WordPress.com", ["wordpress.com"], [r"Do you want to register"]),
    ("Strikingly", ["strikinglydns.com"], [r"page not found"]),
    ("Webflow", ["webflow.io"], [r"The page you are looking for doesn't exist or has been moved"]),
]

def cnames(host):
    chain = []
    cur = host
    for _ in range(6):
        try:
            import subprocess
            out = subprocess.run(["nslookup", "-type=CNAME", cur], capture_output=True, text=True, timeout=10).stdout
            m = re.search(r"canonical name\s*=\s*([^\s]+)", out, re.I)
            if not m or m.group(1).rstrip(".") == cur:
                break
            cur = m.group(1).rstrip("."); chain.append(cur)
        except Exception:
            break
    return chain

def fetch(host):
    body = ""
    for scheme in ("https", "http"):
        try:
            r = urllib.request.urlopen(urllib.request.Request(f"{scheme}://{host}/", headers={"User-Agent": UA}),
                                       timeout=12, context=_CTX)
            body = r.read(4000).decode("utf-8", "replace"); break
        except urllib.error.HTTPError as e:
            body = e.read(4000).decode("utf-8", "replace"); break
        except Exception:
            continue
    return body

def check(host):
    chain = cnames(host)
    body = fetch(host)
    hits = []
    target_cname = chain[-1] if chain else host
    for svc, suffixes, pats in FINGERPRINTS:
        if any(s in target_cname.lower() for s in suffixes) or any(s in host.lower() for s in suffixes):
            for p in pats:
                if re.search(p, body, re.I):
                    hits.append({"service": svc, "fingerprint": p, "cname": target_cname}); break
    return {"target": host, "ok": True, "subdomain": host, "cname_chain": chain, "claimable": bool(hits), "hits": hits,
            "findings": [{"id": "subdomain-takeover", "severity": "high",
                          "detail": f"subdomain {host} -> {target_cname} returns the {hits[0]['service']} deprovisioned fingerprint ('{hits[0]['fingerprint']}') — the resource is likely CLAIMABLE (re-register to serve content / harvest cookies for {host}). Confirm claim-ability within RoE (CWE-350)."}] if hits else []}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Subdomain-takeover detector")
    ap.add_argument("hosts", nargs="*"); ap.add_argument("--file")
    a = ap.parse_args()
    hosts = a.hosts or [l.strip() for l in open(a.file, encoding="utf-8") if l.strip()]
    out = [check(h) for h in hosts]
    print(json.dumps(out if len(out) > 1 else out[0], indent=2))
