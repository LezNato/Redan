#!/usr/bin/env python
"""wp_fingerprint.py — deterministic WordPress / CMS fingerprint.

Detects WordPress and extracts plugin/theme slugs + versions. Versioning is the
evidence base for known-vulnerable-component findings, so accuracy matters:
  - a plugin ships many assets, some with a BUNDLED lib's own ?ver= — so we take
    the MOST FREQUENT ?ver= per slug (the plugin's own version dominates its
    assets) and list every version seen for transparency;
  - the `generator` meta is authoritative when present (Elementor, WPML, WP core)
    and overrides the asset guess.
Works on a live URL or a saved HTML file (--file). Emits JSON.

Usage:
  python wp_fingerprint.py <url>
  python wp_fingerprint.py --file path/to/homepage.html [--name target]
"""
import os, sys, json, re, argparse
from collections import Counter
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _http import get as http_get

def fetch(url, timeout=25):
    r = http_get(url, timeout=timeout, max_body=5_000_000)
    return "" if r.error else r.text

def fingerprint(html, target):
    is_wp = bool(re.search(r"/wp-(content|includes)/|wp-json", html))
    ver = {}      # (kind,slug) -> Counter of versions
    seen_slugs = set()
    for m in re.finditer(r"/wp-content/(plugins|themes)/([a-z0-9][a-z0-9._-]+)/([^\"'?]*)?(?:\?ver=([0-9][0-9.]*))?", html, re.I):
        kind = "plugin" if m.group(1).lower() == "plugins" else "theme"
        slug = m.group(2).lower()
        seen_slugs.add((kind, slug))
        if m.group(4):
            ver.setdefault((kind, slug), Counter())[m.group(4)] += 1

    generators = re.findall(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html, re.I)
    # authoritative versions from generator metas
    gen = {}
    for g in generators:
        m = re.match(r"\s*Elementor\s+([0-9][0-9.]*)", g, re.I)
        if m: gen[("plugin", "elementor")] = m.group(1)
        m = re.search(r"WPML\s+ver:?\s*([0-9][0-9.]*)", g, re.I)
        if m: gen[("plugin", "sitepress-multilingual-cms")] = m.group(1)
        m = re.match(r"\s*WordPress\s+([0-9][0-9.]*)", g, re.I)
        if m: gen[("core", "wordpress")] = m.group(1)

    components = []
    for key in sorted(seen_slugs):
        c = ver.get(key)
        asset_version = c.most_common(1)[0][0] if c else None
        seen = sorted(c, key=lambda v: (-c[v], v)) if c else []
        if key in gen:                       # generator wins
            version, source = gen[key], "generator meta"
        elif asset_version:
            version, source = asset_version, "asset ?ver= (modal)"
        else:
            version, source = None, "path (version unknown)"
        components.append({"type": key[0], "slug": key[1], "version": version,
                           "versions_seen": seen, "source": source})
    if ("core", "wordpress") in gen:
        components.insert(0, {"type": "core", "slug": "wordpress",
                              "version": gen[("core", "wordpress")], "versions_seen": [],
                              "source": "generator meta"})

    versioned = [c for c in components if c["version"]]
    findings = []
    if versioned:
        findings.append({"id": "component-versions-disclosed", "severity": "info",
                         "detail": "; ".join(f"{c['slug']} {c['version']}" for c in versioned)})
    return {"target": target, "ok": True, "is_wordpress": is_wp,
            "components": components, "generators": generators,
            "lead": "map each component+version to known CVEs (verifier; a version match is a lead until confirmed). When versions_seen has >1 value, confirm the plugin version via the plugin's own readme.txt Stable tag.",
            "findings": findings}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Deterministic WordPress / CMS fingerprint.")
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument("url", nargs="?", help="target URL to fetch and fingerprint")
    grp.add_argument("--file", help="saved HTML file to fingerprint instead of a live URL")
    ap.add_argument("--name", help="target label attached to the output (default: url or file path)")
    args = ap.parse_args()
    if args.file:
        name = args.name or args.file
        with open(args.file, encoding="utf-8", errors="replace") as fh:
            html = fh.read()
        print(json.dumps(fingerprint(html, name), indent=2))
    else:
        print(json.dumps(fingerprint(fetch(args.url), args.url), indent=2))
