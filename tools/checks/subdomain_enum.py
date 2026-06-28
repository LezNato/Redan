#!/usr/bin/env python
"""subdomain_enum.py — subdomain enumeration (subfinder-style), stdlib only, no key.

Aggregates subdomains for a domain from MULTIPLE passive sources (cert transparency,
web archive, passive-DNS APIs), dedupes, and attributes per-source — so one source
being down/rate-limited never silently reads as "no subdomains." The kit's existing
coverage is CT (inside origin_discover) + Wayback (wayback_recon) toward OTHER goals;
this is the dedicated breadth enumerator that feeds takeover_probe / origin_discover
and maps the attack surface.

Optional ACTIVE wordlist brute (`--brute`): resolve `<word>.<domain>` for a wordlist
(built-in + `--wordlist`). Uses the SYSTEM resolver (stdlib socket — no dnspython).
A wildcard-DNS guard runs first (a random unlikely name that resolves => wildcard =>
brute is unreliable => flagged, not trusted).

PASSIVE sources query third-party APIs (crt.sh, archive.org, OTX, urlscan, ...), NOT
the target — zero packets to the target in passive mode. NOTE for client work: these
APIs learn the queried domain (operational-awareness consideration on stealthy gigs).

Usage:
  python subdomain_enum.py <domain>                       # passive aggregation (default)
  python subdomain_enum.py <domain> --brute               # + system-resolver wordlist brute
  python subdomain_enum.py <domain> --brute --wordlist list.txt
"""
import sys, os, re, json, socket, argparse, urllib.request, urllib.parse
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _concurrency import workers

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
TIMEOUT = 25

WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "api", "dev", "staging", "stage", "test",
    "admin", "portal", "vpn", "ns1", "ns2", "smtp", "pop", "imap", "mx", "ftp", "sftp",
    "git", "gitlab", "github", "ci", "jenkins", "jira", "wiki", "confluence", "redmine",
    "app", "apps", "auth", "sso", "id", "identity", "account", "accounts", "secure",
    "shop", "store", "pay", "payment", "checkout", "cdn", "static", "assets", "media",
    "img", "images", "docs", "doc", "help", "support", "kb", "forum", "community",
    "m", "mobile", "new", "old", "demo", "sandbox", "qa", "uat", "prod", "internal",
    "intranet", "extranet", "office", "backup", "backups", "db", "database", "cache",
    "status", "monitor", "metrics", "grafana", "kibana", "prometheus", "log", "logs",
    "cpanel", "webdisk", "whm", "plesk", "autodiscover", "autoconfig", "owa", "exchange",
    "crm", "erp", "hr", "sales", "analytics", "track", "tracking", "go", "link", "links",
    "panel", "manage", "manager", "console", "dashboard", "control", "config", "cfg",
    "direct", "origin", "server", "host", "cloud", "aws", "azure", "gcp", "service",
    "services", "ws", "wss", "socket", "realtime", "chat", "bot", "preview", "edge",
]


def _norm(target):
    host = urllib.parse.urlparse(target).netloc or target.split("/")[0]
    return host.split(":")[0].strip(".").lower()


def _get(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json,text/html;q=0.9,*/*;q=0.1"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.read().decode("utf-8", "replace")
    except Exception:
        return None


def _keep(name, domain):
    n = name.strip().lstrip("*.").strip(".").lower()
    if not n or " " in n or "/" in n:
        return None
    if n == domain or n.endswith("." + domain):
        return n
    return None


def src_crtsh(domain):
    raw = _get(f"https://crt.sh/?q=%25.{domain}&output=json")
    if raw is None:
        return set(), "error"
    out = set()
    try:
        for row in json.loads(raw):
            for n in str(row.get("name_value", "")).split("\n"):
                k = _keep(n, domain)
                if k:
                    out.add(k)
    except Exception:
        return set(), "error"
    return out, "ok"


def src_wayback(domain):
    raw = _get("https://web.archive.org/cdx/search/cdx?url=*." + domain + "/*&output=json&fl=original&collapse=urlkey&limit=4000")
    if raw is None:
        return set(), "error"
    out = set()
    try:
        for row in json.loads(raw)[1:]:
            for m in re.findall(r"([A-Za-z0-9_.-]+\." + re.escape(domain) + r")", row[0]):
                k = _keep(m, domain)
                if k:
                    out.add(k)
    except Exception:
        return set(), "error"
    return out, "ok"


def src_hackertarget(domain):
    raw = _get("https://api.hackertarget.com/hostsearch/?q=" + domain)
    if raw is None:
        return set(), "error"
    if "API count exceeded" in raw or "error" in raw.lower():
        return set(), "rate_limited"
    out = set()
    for line in raw.splitlines():
        k = _keep(line.split(",")[0], domain)
        if k:
            out.add(k)
    return out, "ok"


def src_otx(domain):
    raw = _get("https://otx.alienvault.com/api/v1/indicators/domain/" + domain + "/passive_dns")
    if raw is None:
        return set(), "error"
    out = set()
    try:
        for rec in json.loads(raw).get("passive_dns", []):
            k = _keep(rec.get("hostname", ""), domain)
            if k:
                out.add(k)
    except Exception:
        return set(), "error"
    return out, "ok"


def src_urlscan(domain):
    raw = _get("https://urlscan.io/api/v1/search/?q=domain:" + domain)
    if raw is None:
        return set(), "error"
    out = set()
    try:
        for rec in json.loads(raw).get("results", []):
            for key in ("page", "task"):
                d = rec.get(key, {})
                k = _keep(d.get("domain", "") or d.get("apexDomain", ""), domain)
                if k:
                    out.add(k)
    except Exception:
        return set(), "error"
    return out, "ok"


def src_anubis(domain):
    raw = _get("https://jonlu.ca/anubis/subdomains/" + domain)
    if raw is None:
        return set(), "error"
    out = set()
    try:
        data = json.loads(raw)
        items = data if isinstance(data, list) else data.get("subdomains", [])
        for s in items:
            k = _keep(s, domain)
            if k:
                out.add(k)
    except Exception:
        return set(), "error"
    return out, "ok"


def src_rapiddns(domain):
    raw = _get("https://rapiddns.io/subdomain/" + domain + "?full=1")
    if raw is None:
        return set(), "error"
    out = set()
    for m in re.findall(r">([A-Za-z0-9_.-]+\." + re.escape(domain) + r")<", raw):
        k = _keep(m, domain)
        if k:
            out.add(k)
    return out, "ok"


SOURCES = {
    "crt.sh": src_crtsh, "wayback": src_wayback, "hackertarget": src_hackertarget,
    "otx": src_otx, "urlscan": src_urlscan, "anubis": src_anubis, "rapiddns": src_rapiddns,
}


def _resolve(name):
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(name, None, socket.AF_INET)})
    except Exception:
        return []


def _wildcard(domain):
    """Resolves a random-unlikely name; if it resolves, the domain has wildcard DNS."""
    probe = "redan-nxdomainsentinel-" + re.sub(r"[^a-z0-9]", "", domain)[-6:] + "-zzz." + domain
    return bool(_resolve(probe))


def brute(domain, words, wildcard):
    """System-resolver wordlist brute. Returns {count, resolved:[{name, ips}], wildcard}."""
    hits = []
    if wildcard:
        return {"count": 0, "resolved": [], "wildcard": True,
                "note": "wildcard DNS detected — every name resolves, so brute results are unreliable and omitted (false-positive guard)"}
    candidates = {w + "." + domain for w in words}
    with ThreadPoolExecutor(max_workers=workers(cap=32)) as ex:
        for name, ips in zip(sorted(candidates), ex.map(_resolve, sorted(candidates))):
            if ips:
                hits.append({"name": name, "ips": ips[:4]})
    return {"count": len(hits), "resolved": hits, "wildcard": False}


def run(target, do_brute, wordlist_path):
    domain = _norm(target)
    out = {"target": domain, "ok": True, "passive": True, "sources": {}, "subdomains": [], "count": 0}
    agg = set()
    with ThreadPoolExecutor(max_workers=workers(cap=12)) as ex:
        results = dict(zip(SOURCES.keys(), ex.map(lambda fn: fn(domain), SOURCES.values())))
    up = 0
    for name, (names, status) in results.items():
        out["sources"][name] = {"status": status, "count": len(names)}
        if status == "ok":
            up += 1
        agg |= names
    subs = sorted(agg)
    out["subdomains"] = subs
    out["count"] = len(subs)
    out["sources_up"] = up
    out["total_sources"] = len(SOURCES)

    coverage_gap = (up == 0)
    if coverage_gap:
        out["coverage_gap"] = True
        out["coverage_gap_reason"] = ("every passive source failed (down / rate-limited / blocked) — this is NOT "
                                      "'no subdomains', it is 'sources unreachable here'. Retry, or use --brute.")

    brute_out = None
    if do_brute:
        w = list(WORDLIST)
        if wordlist_path:
            try:
                with open(wordlist_path, encoding="utf-8", errors="ignore") as f:
                    w = list(dict.fromkeys(w + [ln.strip() for ln in f if ln.strip()]))
            except Exception as e:
                out["brute_error"] = f"wordlist unreadable: {e}"
        out["wildcard_dns"] = _wildcard(domain)
        brute_out = brute(domain, w, out["wildcard_dns"])
        # merge brute-only finds into the surface set (attribute separately)
        before = set(subs)
        for h in brute_out.get("resolved", []):
            agg.add(h["name"])
        out["brute"] = brute_out
        out["subdomains"] = sorted(agg)
        out["count"] = len(out["subdomains"])
        out["brute_only"] = sorted(set(out["subdomains"]) - before)

    findings = []
    if subs:
        findings.append({"id": "subdomain-surface", "severity": "info",
                         "detail": f"{len(subs)} subdomain(s) enumerated across {up}/{len(SOURCES)} passive sources"
                                   + (f" + brute" if do_brute else "")
                                   + " — feed to takeover_probe (dangling-CNAME) and origin_discover (origin IP); each is attack surface, not itself a vuln.",
                         "sample": subs[:40]})
    out["findings"] = findings
    out["note"] = ("PASSIVE (queries CT/DNS/archive APIs, not the target). Sources rate-limit / change format — "
                   "per-source status shown; a source down never reads as 'no subdomains'. Brute (--brute) uses the "
                   "SYSTEM resolver (no dnspython) and is wildcard-guarded. NOTE: third-party APIs learn the queried "
                   "domain (operational consideration on stealthy engagements).")
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Subdomain enumeration (subfinder-style, passive + optional brute)")
    ap.add_argument("domain", help="domain or URL to enumerate")
    ap.add_argument("--brute", action="store_true", help="also run a system-resolver wordlist brute")
    ap.add_argument("--wordlist", help="extra brute wordlist (one prefix per line)")
    ap.add_argument("--timeout", type=int, default=TIMEOUT, help="per-source HTTP timeout (s)")
    a = ap.parse_args()
    if a.timeout != TIMEOUT:
        globals()["TIMEOUT"] = a.timeout  # _get reads the module global at call time
    print(json.dumps(run(a.domain, a.brute, a.wordlist), indent=2))
