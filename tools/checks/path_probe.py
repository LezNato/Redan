#!/usr/bin/env python
"""path_probe.py — deterministic sensitive-path / well-known prober (SPA-aware).

Checks a built-in list of high-signal paths and reports reachable ones, flagging
exposed secrets/VCS/backups. NON-destructive GET, rate-limited. Emits JSON.

SPA-AWARE: single-page apps and
catch-all routers return 200 + the app shell for ANY path, which naively reads as
"every sensitive file is exposed." So we first CALIBRATE against a known-
nonexistent path; any 200 whose body matches that fallback is tagged `spa-fallback`
and is NOT counted as reachable. Only a 200 that DIFFERS from the fallback (real
file / endpoint) is flagged. NOTE: only probes the host in the base URL — the
caller is responsible for scope.

Usage: python path_probe.py <base-url> [--full]
"""
import sys, os, json, ssl, hashlib, urllib.request, urllib.error, argparse
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _concurrency import workers

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

CORE = [
    ".git/HEAD", ".git/config", ".env", ".env.bak", "wp-config.php.bak", "config.php.bak",
    "backup.zip", "backup.tar.gz", "db.sql", "dump.sql", ".DS_Store",
    ".well-known/security.txt", "robots.txt", "sitemap.xml",
    "wp-login.php", "wp-admin/", "xmlrpc.php", "wp-json/", "readme.html",
    "admin/", "administrator/", "phpmyadmin/", "server-status", "actuator/health",
    ".svn/entries", "package.json", "composer.json", "/.well-known/openid-configuration",
]
FULL_EXTRA = [
    "wp-content/debug.log", "wp-content/uploads/", "api/", "graphql", "swagger.json",
    "openapi.json", "/api-docs", ".gitlab-ci.yml", "Dockerfile", "docker-compose.yml",
    "id_rsa", ".aws/credentials", "web.config", ".htaccess", "crossdomain.xml",
]
SENSITIVE = {".git/HEAD", ".git/config", ".env", ".env.bak", "wp-config.php.bak", "config.php.bak",
             "backup.zip", "backup.tar.gz", "db.sql", "dump.sql", "wp-content/debug.log",
             "id_rsa", ".aws/credentials", ".svn/entries", ".gitlab-ci.yml"}

def get(url, timeout=12):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": UA})
    try:
        r = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = r.read(60000)
        return r.getcode(), (r.headers.get("Content-Type") or "").split(";")[0].strip().lower(), body
    except urllib.error.HTTPError as e:
        try: body = e.read(60000)
        except Exception: body = b""
        return e.code, (e.headers.get("Content-Type") if e.headers else "") or "", body
    except Exception:
        return None, None, b""

def sig(body):
    return hashlib.sha256(body or b"").hexdigest()[:16], len(body or b"")

def check(base, full=False, conc=None):
    base = base.rstrip("/") + "/"
    # calibrate against SEVERAL definitely-nonexistent paths of different shapes — a WAF /
    # bot-challenge / soft-404 may treat .txt vs extensionless vs dir differently AND vary the
    # catch-all page slightly per request (real-world case), defeating a single calibration shot.
    CALIB = ["pt-probe-nonexistent-7f3a9c2e.txt", "pt-probe-nope-3a1b9c2e",
             "pt-probe-7c2/missing-9f1d/", "pt-probe-nonexistent-8b4d.json"]
    baselines = []
    for c in CALIB:
        s, ct, b = get(base + c)
        if s == 200:
            baselines.append((sig(b)[0], ct, sig(b)[1]))
    paths = CORE + (FULL_EXTRA if full else [])
    n = workers(cap=64, want=conc)   # core-scaled (cores*4, bounded; higher = more target load)
    with ThreadPoolExecutor(max_workers=n) as ex:                       # parallel probe
        fetched = list(ex.map(lambda p: (p,) + get(base + p.lstrip("/")), paths))
    # post-hoc: even if calibration didn't 200, a WAF catch-all shows as MANY 200s clustered at
    # one body length — detect that cluster and treat it as the not-found/challenge shell.
    two_hundreds = [(sig(body)[0], ct, sig(body)[1]) for (p, s, ct, body) in fetched if s == 200]
    if len(two_hundreds) >= 5:
        lens = sorted(bl for (_, _, bl) in two_hundreds)
        med = lens[len(lens) // 2]
        cluster = [t for t in two_hundreds if abs(t[2] - med) <= max(256, int(med * 0.03))]
        if len(cluster) >= 0.6 * len(two_hundreds):
            baselines.append((None, cluster[0][1], med))   # synthetic shell baseline
    catchall = len(baselines) > 0
    def is_shell(bhash, ct, blen):
        for (chash, cct, cblen) in baselines:
            if (chash and bhash == chash) or (ct == cct and abs(blen - cblen) <= max(256, int(cblen * 0.03))):
                return True
        return False
    results, reachable, findings = [], [], []
    for p, s, ct, body in fetched:   # classify in original order (CPU-light)
        bhash, blen = sig(body)
        kind = "other"
        if s == 200:
            if catchall and is_shell(bhash, ct, blen):
                kind = "spa-fallback"   # indistinguishable from the not-found/challenge shell → NOT a real hit
            else:
                kind = "real"
                reachable.append(p)
                if p in SENSITIVE:
                    findings.append({"id": "sensitive-file-exposed", "severity": "high",
                                     "detail": f"{p} reachable (HTTP 200, distinct from app shell) — verify contents"})
        results.append({"path": p, "status": s, "kind": kind})
    return {"target": base, "ok": True, "probed": len(paths), "concurrency": n,
            "catch_all_200": catchall,
            "note": ("site returns 200+shell for unknown paths; 'spa-fallback' results were filtered out"
                     if catchall else "site 404s unknown paths; 200 = real"),
            "reachable_200_real": reachable, "results": results, "findings": findings}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Deterministic sensitive-path / well-known prober (SPA-aware).")
    ap.add_argument("url", metavar="base-url", help="target base URL")
    ap.add_argument("--full", action="store_true", help="also probe the extended FULL_EXTRA path set")
    ap.add_argument("--concurrency", type=int, default=None, help="worker override (default cores*4, bounded)")
    args = ap.parse_args()
    print(json.dumps(check(args.url, args.full, args.concurrency), indent=2))
