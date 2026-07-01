#!/usr/bin/env python
"""screenshot_gallery.py — bulk web-page screenshot triage (gowitness/aquatone-style).

Renders a list of web targets in a real headless Chromium and writes a single
HTML GALLERY (thumbnail + HTTP status + page title + final URL per target) for
fast visual triage of a large surface — the "which of these 200 hosts is a login
page / a default install / a parked domain / an admin panel" pass that a status
code alone can't answer. Reuses the same Playwright channel as browser_probe (so
it renders SPAs and survives a JS-challenge interstitial as whatever the page
actually shows).

A capture tool, not a vuln detector: it emits the rendered evidence (PNG + the
gallery), no disposition. A DEAD/unreachable host produces an error row and NO
screenshot — never a blank/fake thumbnail (the recon analogue of the kit's
false-positive discipline: absence is recorded as absence).

WEB-APP SCOPE: screenshots in-scope web pages/sites. Bounded (one navigation per
target); honors RoE (a GET render, no active payloads). Sequential by default
(one browser, page-by-page) — large lists take time but stay gentle on the target.
Requires: playwright + chromium (lazy-imported; on a real target use the same
proxy/channel guidance as browser_probe for graylisted/JS-challenge edges).

Usage:
  python screenshot_gallery.py https://a.example https://b.example
  python screenshot_gallery.py --list hosts.txt --out-dir engagements/<name>/evidence/shots
  python screenshot_gallery.py --targets a.example,b.example --full-page --timeout 25000
"""
import argparse
import hashlib
import html
import json
import os
import sys
import urllib.parse

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


def collect_targets(positional, list_file, targets_csv):
    """Gather targets from positionals + a file + a CSV; normalize a bare host to a
    URL (https, with an http fallback on failure); dedupe preserving order. Returns
    a list of (url, auto_https) — auto_https drives the http retry."""
    raw = list(positional or [])
    if list_file:
        with open(list_file, encoding="utf-8", errors="replace") as fh:
            raw += [ln.strip() for ln in fh if ln.strip() and not ln.strip().startswith("#")]
    if targets_csv:
        raw += [x.strip() for x in targets_csv.split(",") if x.strip()]
    out, seen = [], set()
    for x in raw:
        auto = "://" not in x
        url = ("https://" + x) if auto else x
        if url not in seen:
            seen.add(url)
            out.append((url, auto))
    return out


def _fname(url):
    host = urllib.parse.urlparse(url).netloc.replace(":", "_") or "site"
    return f"{host}_{hashlib.md5(url.encode()).hexdigest()[:8]}.png"


def shoot(browser, url, out_dir, viewport, full_page, timeout):
    """Render one target, capture status/title/screenshot. An unreachable host
    returns a row with `error` and NO screenshot."""
    row = {"url": url, "final_url": None, "status": None, "title": None, "screenshot": None}
    ctx = browser.new_context(viewport=viewport, user_agent=UA, ignore_https_errors=True)
    pg = ctx.new_page()
    try:
        resp = pg.goto(url, wait_until="domcontentloaded", timeout=timeout)
        row["status"] = resp.status if resp else None
        try:
            pg.wait_for_load_state("networkidle", timeout=3000)
        except Exception:
            pass  # best-effort settle; capture whatever has rendered
        row["final_url"] = pg.url
        row["title"] = (pg.title() or "")[:160]
        fn = _fname(url)
        pg.screenshot(path=os.path.join(out_dir, fn), full_page=full_page)
        row["screenshot"] = fn  # relative to the gallery (same dir)
    except Exception as e:
        row["error"] = str(e)[:200]
    finally:
        ctx.close()
    return row


_GALLERY_CSS = """
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#0b0e14;color:#c8d0dc;font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
h1{font-size:18px;padding:18px 22px;margin:0;border-bottom:1px solid #1c2230;color:#e6edf6}
.sub{color:#7a8699;font-size:12px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px;padding:22px}
.card{background:#11151f;border:1px solid #1c2230;border-radius:10px;overflow:hidden;display:flex;flex-direction:column}
.card img{width:100%;height:200px;object-fit:cover;object-position:top;background:#070a10;border-bottom:1px solid #1c2230}
.noshot{height:200px;display:flex;align-items:center;justify-content:center;color:#5a6678;background:#0d1118;border-bottom:1px solid #1c2230;font-size:12px}
.meta{padding:10px 12px;display:flex;flex-direction:column;gap:4px;min-width:0}
.meta a{color:#7db5ff;text-decoration:none;word-break:break-all}
.t{color:#9aa6b8;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.s{display:inline-block;font-size:11px;font-weight:600;padding:1px 7px;border-radius:6px;margin-right:6px}
.s2{background:#10331f;color:#5fd38d}.s3{background:#33300f;color:#e3c558}
.s4{background:#3a2412;color:#f0a35e}.s5{background:#3a1518;color:#f07a7a}.s0{background:#2a2f3a;color:#8a96a8}
"""


def build_gallery(rows, out_dir):
    cards = []
    for r in rows:
        shot = r.get("screenshot")
        thumb = (f'<a href="{html.escape(shot)}" target="_blank"><img src="{html.escape(shot)}" loading="lazy"></a>'
                 if shot else f'<div class="noshot">{html.escape((r.get("error") or "no screenshot")[:60])}</div>')
        st = r.get("status")
        cls = f"s{st // 100}" if isinstance(st, int) else "s0"
        label = str(st) if st is not None else "ERR"
        furl = html.escape(r.get("final_url") or r["url"])
        title = html.escape(r.get("title") or "")
        cards.append(
            f'<div class="card">{thumb}<div class="meta">'
            f'<div><span class="s {cls}">{label}</span>'
            f'<a href="{furl}" target="_blank">{furl}</a></div>'
            f'<div class="t">{title}</div></div></div>')
    doc = (f'<!doctype html><html><head><meta charset="utf-8">'
           f'<title>Redan — screenshot triage</title><style>{_GALLERY_CSS}</style></head><body>'
           f'<h1>Redan — screenshot triage '
           f'<span class="sub">{len(rows)} targets · '
           f'{sum(1 for r in rows if r.get("screenshot"))} captured</span></h1>'
           f'<div class="grid">{"".join(cards)}</div></body></html>')
    path = os.path.join(out_dir, "gallery.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path


def main():
    ap = argparse.ArgumentParser(description="Bulk web-page screenshot triage gallery")
    ap.add_argument("url", nargs="*", help="target URL(s) or bare host(s)")
    ap.add_argument("--list", help="file of targets, one per line (# comments ok)")
    ap.add_argument("--targets", help="comma-separated targets")
    ap.add_argument("--out-dir", default="screenshots", help="output dir for PNGs + gallery.html")
    ap.add_argument("--full-page", action="store_true", help="full-page shots (default: above-the-fold)")
    ap.add_argument("--width", type=int, default=1280)
    ap.add_argument("--height", type=int, default=800)
    ap.add_argument("--timeout", type=int, default=20000, help="per-target nav timeout (ms)")
    args = ap.parse_args()

    targets = collect_targets(args.url, args.list, args.targets)
    if not targets:
        print(json.dumps({"tool": "screenshot_gallery", "target": "", "ok": False,
                          "error": "no targets (give URLs, --list, or --targets)"})); sys.exit(2)
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(json.dumps({"tool": "screenshot_gallery", "target": f"{len(targets)} target(s)", "ok": False,
                          "error": "playwright not installed: pip install playwright && playwright install chromium"}))
        sys.exit(1)

    os.makedirs(args.out_dir, exist_ok=True)
    viewport = {"width": args.width, "height": args.height}
    rows = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--disable-blink-features=AutomationControlled"])
        try:
            for url, auto in targets:
                row = shoot(browser, url, args.out_dir, viewport, args.full_page, args.timeout)
                if row.get("error") and auto:  # bare host given as https — retry http
                    alt = "http://" + url[len("https://"):]
                    row2 = shoot(browser, alt, args.out_dir, viewport, args.full_page, args.timeout)
                    if not row2.get("error"):
                        row = row2
                rows.append(row)
        finally:
            browser.close()

    gallery = build_gallery(rows, args.out_dir)
    captured = sum(1 for r in rows if r.get("screenshot"))
    print(json.dumps({
        "tool": "screenshot_gallery",
        "target": targets[0][0] if len(targets) == 1 else f"{len(targets)} targets",
        "ok": True, "captured": captured, "failed": len(rows) - captured,
        "out_dir": args.out_dir, "gallery": gallery, "results": rows,
        "note": "Visual-triage capture (no disposition). A dead host = an error row + NO "
                "screenshot, never a blank thumbnail. Open gallery.html to triage.",
    }, indent=2))


if __name__ == "__main__":
    main()
