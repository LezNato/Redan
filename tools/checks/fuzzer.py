#!/usr/bin/env python
"""fuzzer.py — content/directory discovery + parameter fuzzing (stdlib, core-scaled).

  dir   : discover paths from a wordlist, CALIBRATED against a known-404 baseline so
          SPA / soft-404 catch-alls don't produce false positives (same trick as
          path_probe). Flags reachable (200-real), protected (401/403), and error (5xx).
  param : send probe payloads to a parameter and flag reflections (XSS lead),
          SQL-error signatures (SQLi lead), and traversal markers.

Discovery / leads only — the verifier confirms exploitability. ACTIVE: honor
--concurrency (use prod_concurrency on live sites; lower = gentler).

Usage:
  python fuzzer.py dir <base-url> [--wordlist f] [--ext .php,.bak,.zip] [--concurrency N]
  python fuzzer.py param <url> -p <param> [--concurrency N]
"""
import sys, os, re, ssl, json, hashlib, argparse, urllib.request, urllib.error
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _concurrency import workers

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
SQL_ERRORS = ["sql syntax", "mysql_fetch", "you have an error in your sql", "ora-0", "sqlite", "psql:",
              "unclosed quotation", "quoted string not properly terminated", "pg_query", "sqlstate",
              "syntax error at or near", "warning: mysqli"]
WORDLIST = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php", "user", "users", "account",
    "api", "api/v1", "api/v2", "graphql", "graphiql", "swagger", "swagger-ui", "api-docs", "openapi.json",
    "config", "config.php", "config.json", "configuration", ".env", ".env.bak", "settings.py",
    "backup", "backup.zip", "backup.sql", "db.sql", "dump.sql", "database.sql", "site.tar.gz", "www.zip",
    ".git/config", ".git/HEAD", ".svn/entries", ".hg", ".DS_Store", "WEB-INF/web.xml",
    "test", "dev", "staging", "debug", "console", "actuator", "actuator/health", "actuator/env",
    "metrics", "status", "server-status", "phpinfo.php", "info.php", "robots.txt", "sitemap.xml",
    "upload", "uploads", "files", "tmp", "temp", "logs", "log", "error.log", "access.log",
    "phpmyadmin", "adminer.php", "pma", "dbadmin", "mysql", "manager/html",
    "secret", "secrets", "private", "internal", "old", "bak", "backup.tar.gz", "credentials.json",
    "id_rsa", ".ssh/id_rsa", ".aws/credentials", ".npmrc", ".dockercfg", "docker-compose.yml",
    "jenkins", "gitlab", "grafana", "kibana", "prometheus", "redis", "elasticsearch",
    "register", "signup", "password-reset", "reset", "forgot", "logout", "profile", "dashboard",
    "cgi-bin", "includes", "vendor", "node_modules", "storage", "cache", "assets", "static",
]
PARAM_PAYLOADS = {
    "reflect": "ptxss<9z7>q",
    "sqli_quote": "'",
    "sqli_bool": "1' OR '1'='1",
    "traversal": "../../../../etc/passwd",
    "mixed": "'\"><pt",
}

def get(url, timeout=12):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        r = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = r.read(20000); return r.getcode(), dict(r.headers).get("Content-Type", ""), body
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}).get("Content-Type", ""), (e.read(4000) if hasattr(e, "read") else b"")
    except Exception:
        return None, "", b""

def sig(b): return hashlib.sha1(b or b"").hexdigest(), len(b or b"")

def fuzz_dir(base, words, exts, conc):
    base = base.rstrip("/") + "/"
    cs, cct, cbody = get(base + "pt-fuzz-nope-7f3a9c2e1b/")
    cbh, cbl = sig(cbody); catchall = (cs == 200)
    cands = []
    for w in words:
        cands.append(w)
        for ext in exts:
            cands.append(w + ext)
    def probe(w):
        s, ct, body = get(base + w.lstrip("/"))
        bh, bl = sig(body)
        kind = "other"
        if s == 200:
            kind = "spa-fallback" if (catchall and (bh == cbh or (ct == cct and abs(bl - cbl) <= max(64, int(cbl * 0.02))))) else "real"
        elif s in (301, 302, 307, 308): kind = "redirect"
        elif s in (401, 403): kind = "protected"
        elif s and s >= 500: kind = "error"
        return {"path": w, "status": s, "kind": kind}
    with ThreadPoolExecutor(max_workers=workers(cap=64, want=conc)) as ex:
        results = [r for r in ex.map(probe, cands) if r["status"] is not None]
    hits = [r for r in results if r["kind"] in ("real", "protected", "error", "redirect")]
    findings = []
    for r in hits:
        if r["kind"] == "real":
            findings.append({"id": "content-discovered", "severity": "info",
                             "detail": f"{r['path']} reachable (HTTP 200, distinct from app shell) — review"})
        elif r["kind"] == "protected":
            findings.append({"id": "protected-resource", "severity": "info",
                             "detail": f"{r['path']} exists but auth-gated (HTTP {r['status']})"})
    return {"target": base, "ok": True, "mode": "dir", "probed": len(cands), "catch_all_200": catchall,
            "concurrency": workers(cap=64, want=conc), "hits": hits, "findings": findings}

def fuzz_param(url, param, conc):
    u = urlparse(url); q = parse_qs(u.query)
    if param not in q:
        q[param] = ["1"]
    def build(val):
        qq = {k: v[:] for k, v in q.items()}; qq[param] = [val]
        return urlunparse(u._replace(query=urlencode(qq, doseq=True)))
    bs, bct, bbody = get(build("ptbaseline1"))
    _, bl = sig(bbody)
    def probe(item):
        name, payload = item
        s, ct, body = get(build(payload))
        text = body.decode("latin-1", "replace")
        leads = []
        if payload in text:
            leads.append("payload reflected verbatim")
        low = text.lower()
        for e in SQL_ERRORS:
            if e in low:
                leads.append(f"SQL error signature ('{e}')"); break
        if "root:x:0:0" in text or "[extensions]" in low:
            leads.append("file-read content in response")
        return {"payload_class": name, "status": s, "leads": leads}
    with ThreadPoolExecutor(max_workers=workers(cap=16, want=conc)) as ex:
        rows = list(ex.map(probe, PARAM_PAYLOADS.items()))
    findings = []
    for r in rows:
        for lead in r["leads"]:
            sev = "medium" if "reflected" in lead else ("high" if "SQL" in lead or "file-read" in lead else "low")
            findings.append({"id": "param-fuzz-lead", "severity": sev,
                             "detail": f"param '{param}' [{r['payload_class']}]: {lead} (LEAD — verifier confirms)"})
    return {"target": url, "ok": True, "mode": "param", "param": param, "results": rows, "findings": findings}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["dir", "param"]); ap.add_argument("url")
    ap.add_argument("-p", "--param"); ap.add_argument("--wordlist"); ap.add_argument("--ext", default="")
    ap.add_argument("--concurrency", type=int, default=None)
    a = ap.parse_args()
    if a.mode == "dir":
        words = [w.strip() for w in open(a.wordlist, encoding="utf-8", errors="replace")] if a.wordlist else WORDLIST
        words = [w for w in words if w and not w.startswith("#")]
        exts = [e for e in a.ext.split(",") if e]
        print(json.dumps(fuzz_dir(a.url, words, exts, a.concurrency), indent=2))
    else:
        if not a.param: print("param mode needs -p <param>"); sys.exit(2)
        print(json.dumps(fuzz_param(a.url, a.param, a.concurrency), indent=2))
