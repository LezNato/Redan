#!/usr/bin/env python
"""redact.py — deterministic credential/secret + PII redactor + tree scanner.

THE load-bearing control for evidence hygiene (red-team finding: every "redact
secrets" rule was prose to an LLM with zero enforcement). Two concern classes,
two severities:

  * SECRET  — credentials/tokens/keys/session material. A leak is BLOCKING:
              `scan` exits nonzero so the QA gate / a hook refuses to ship.
  * PII     — emails / SSNs / payment cards. Reported as ADVISORY by default
              (a report legitimately carries a client CONTACT email); `--strict`
              makes PII blocking too. `file`/stdin redaction strips BOTH.

Modes:
  scan <path> [--strict]   walk a file/dir, report hits; EXIT 1 on any SECRET
                           hit (or any hit with --strict).
  file <in> [out]          write a redacted copy (in-place if no out).
  -                        read stdin, write redacted stdout (pipe transcripts).

Allowlist (for the toolkit's own docs/tests/examples, NOT engagement evidence):
a value that is an obvious placeholder (`<key>`, `${VAR}`, `***`, `your_token`)
is never flagged; a line carrying `pragma: allowlist secret` (or `redact-allow`)
is skipped; a file whose header carries `redact-allow-file` is skipped entirely.
Evidence captures never carry these markers, so real leaks still BLOCK.

Findings reproduce by ROLE, never by token — live session material has no
business in evidence/findings/report. This makes that mechanical, not hopeful.
"""
import sys, os, re, json

# ---- pattern sets ----------------------------------------------------------
# (label, category, compiled pattern, replacement). Order matters (headers/
# structured before generic). Negative lookaheads avoid re-matching an already
# -[REDACTED] value so redact -> rescan converges to clean. category in
# {"secret","pii"}; "secret" hits are BLOCKING.
P = [
    # --- structured credential headers / cookies (secret) ---
    ("set-cookie", "secret",
     re.compile(r'(?im)^(set-cookie\s*:\s*[^=;\s]+=)(?!\[REDACTED)([^;\r\n]+)'), r'\1[REDACTED]'),
    ("auth-header", "secret",
     re.compile(r'(?im)^(authorization|proxy-authorization|cookie|x-auth-token|x-api-key|x-csrf-token|x-xsrf-token)(\s*:\s*)(?!\s*\[REDACTED).+$'),
     r'\1\2[REDACTED]'),
    # JSON-value auth header (indented/quoted from browser-channel / HAR / "Copy as fetch" evidence) —
    # the ^-anchored pattern above misses `"Authorization": "Basic ..."`. Scoped to real auth SCHEMES so it
    # catches the Basic/Digest gap without flagging benign committed JSON (Bearer/JWT are caught elsewhere).
    ("auth-header-json", "secret",
     re.compile(r'(?i)"(authorization|proxy-authorization)"\s*:\s*"(?!\[REDACTED)((?:Basic|Digest|Negotiate|NTLM|AWS4-HMAC-SHA256)\s+[^"]{6,})"'),
     r'"\1": "[REDACTED]"'),
    ("bearer", "secret",
     re.compile(r'(?i)\bbearer\s+(?!\[REDACTED)(?=[A-Za-z0-9._~+/\-]*[0-9._~+/\-])[A-Za-z0-9._~+/\-]{8,}=*'), 'Bearer [REDACTED]'),
    ("jwt", "secret",
     re.compile(r'\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}'), '[REDACTED:jwt]'),
    ("cookie-pair", "secret",
     re.compile(r'(?i)\b(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|wordpress_logged_in_[a-f0-9]+|wordpress_sec_[a-f0-9]+|XSRF-TOKEN|csrftoken|connect\.sid)=(?!\[REDACTED)([^;\s]+)'),
     r'\1=[REDACTED]'),
    # --- key=value secrets; the key may carry a prefix (db_password, MY_API_KEY) ---
    ("kv-secret", "secret",
     re.compile(r'(?i)([\w.\-]*(?:passwd|password|pwd|secret|api[_\-]?key|apikey|access[_\-]?token|refresh[_\-]?token|id[_\-]?token|auth[_\-]?token|client[_\-]?secret|session[_\-]?token|private[_\-]?key|x-amz-security-token))(["\']?\s*[=:]\s*["\']?)(?!\[REDACTED)([^"\'&\s,;}]{3,})'),
     r'\1\2[REDACTED]'),
    # --- unlabeled, self-identifying secrets (no key needed) ---
    ("aws-access-key", "secret", re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'), '[REDACTED:aws-key]'),
    ("github-token", "secret", re.compile(r'\bgh[posru]_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b'), '[REDACTED:gh-token]'),
    ("google-api-key", "secret", re.compile(r'\bAIza[0-9A-Za-z_\-]{35}\b'), '[REDACTED:google-key]'),
    ("slack-token", "secret", re.compile(r'\bxox[baprs]-[A-Za-z0-9\-]{10,}\b'), '[REDACTED:slack-token]'),
    ("stripe-secret-key", "secret", re.compile(r'\b[rs]k_(?:live|test)_[0-9A-Za-z]{16,}\b'), '[REDACTED:stripe-key]'),
    ("private-key-block", "secret",
     re.compile(r'-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----', re.S),
     '[REDACTED:private-key]'),
    ("url-credentials", "secret",
     re.compile(r'\b([a-z][a-z0-9+.\-]*://)([^/:@\s]+):(?!\[REDACTED)([^/@\s]+)@'), r'\1\2:[REDACTED]@'),
    # --- PII (advisory unless --strict) ---
    ("email", "pii", re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED:email]'),
    ("us-ssn", "pii", re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[REDACTED:ssn]'),
]

# Luhn-validated payment-card numbers (regex alone over-matches; validate digits).
_PAN_CAND = re.compile(r'(?<![\d.])(?:\d[ -]?){13,19}(?<![ -])')

# Binary/opaque files we can't meaningfully regex — everything else is scanned
# (so .env / .pem / .key / extensionless evidence are NOT silently skipped).
BINARY_EXT = {
    "png", "jpg", "jpeg", "gif", "webp", "ico", "bmp", "pdf", "zip", "tar", "gz",
    "tgz", "bz2", "xz", "7z", "rar", "exe", "dll", "so", "dylib", "bin", "o", "a",
    "class", "pyc", "pyo", "wasm", "woff", "woff2", "ttf", "otf", "eot", "mp3",
    "mp4", "avi", "mov", "mkv", "wav", "flac", "ogg", "webm", "jar", "war",
    "docx", "xlsx", "pptx", "odt",
}
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".playwright-mcp"}
MAX_SIZE = 8 * 1024 * 1024  # 8 MB — don't try to scan a huge blob line-by-line

# A VALUE that is obviously a placeholder, not a live secret (env-var docs, configs,
# already-redacted evidence). Matched with fullmatch() against the captured VALUE only
# — NOT a substring of the whole key=value match — so a real token that merely CONTAINS
# a run like 'xxxx' (e.g. session_token=a1b2c3xxxxd4...) is still flagged. The scan does
# not block on these; redaction still replaces them (over-redacting a placeholder is harmless).
_PLACEHOLDER = re.compile(
    r"<[A-Za-z0-9_.\-]*>"              # <key>, <your-token>
    r"|\$\{[A-Za-z0-9_.\-]*\}"         # ${VAR}
    r"|%[A-Za-z0-9_.\-]+%"             # %VAR%
    r"|\*{3,}|x{4,}|\.{3,}"            # ***  xxxx  ...  (a WHOLE all-x/star/dot value)
    r"|\[REDACTED[^\]]*\]"             # already-redacted
    r"|(?:your|my)[_\-][A-Za-z0-9_\-]*"   # your_token
    r"|changeme|placeholder|example|dummy|redacted|todo",
    re.I)


def _placeholder_value(m):
    """The value a placeholder check should consider: the last capture group (the
    value in key/sep/value patterns) or, for ungrouped patterns, the whole match."""
    return ((m.groups()[-1] if m.groups() else m.group(0)) or "").strip()
# Allowlist (like gitleaks): a line carrying a LINE marker is skipped; a file whose
# header carries the FILE marker is skipped entirely (intentional fixture files).
# Evidence captures never carry these, so real leaks still block.
LINE_ALLOW = ("redact-allow", "pragma: allowlist secret")
FILE_ALLOW = "redact-allow-file"


def _luhn_ok(digits):
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _redact_pan(s):
    """Redact Luhn-valid 13-19 digit card numbers; count hits."""
    hits = [0]

    def repl(m):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            hits[0] += 1
            return "[REDACTED:pan]"
        return m.group(0)

    return _PAN_CAND.sub(repl, s), hits[0]


def redact_text(s):
    """Redact SECRET + PII (used by file/stdin modes). Returns (text, total_hits)."""
    hits = 0
    for _, _cat, pat, repl in P:
        s, n = pat.subn(repl, s)
        hits += n
    s, n = _redact_pan(s)
    hits += n
    return s, hits


def is_scannable(path):
    ext = os.path.splitext(path)[1].lower().lstrip(".")
    if ext in BINARY_EXT:
        return False
    try:
        return os.path.getsize(path) <= MAX_SIZE
    except OSError:
        return False


def scan_file(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except Exception:
        return []
    lines = text.splitlines()
    if FILE_ALLOW in "\n".join(lines[:25]):   # whole-file allowlist (fixture files)
        return []
    found = []
    for i, line in enumerate(lines, 1):
        if any(mk in line for mk in LINE_ALLOW):   # line-level allowlist
            continue
        for label, cat, pat, _ in P:
            if label == "private-key-block":
                continue  # multi-line; handled below
            m = pat.search(line)
            if m and not _PLACEHOLDER.fullmatch(_placeholder_value(m)):  # skip ONLY whole-placeholder values
                found.append({"file": path, "line": i, "pattern": label, "category": cat})
        # Luhn-validated PAN on this line
        for m in _PAN_CAND.finditer(line):
            digits = re.sub(r"\D", "", m.group(0))
            if 13 <= len(digits) <= 19 and _luhn_ok(digits):
                found.append({"file": path, "line": i, "pattern": "pan", "category": "pii"})
                break
    # multi-line private key block (line of the BEGIN marker)
    for m in re.finditer(r'-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----', text):
        ln = text.count("\n", 0, m.start()) + 1
        if any(mk in lines[ln - 1] for mk in LINE_ALLOW):
            continue
        found.append({"file": path, "line": ln, "pattern": "private-key-block", "category": "secret"})
    return found


def scan(root, strict=False):
    if os.path.isfile(root):
        targets = [root]
    else:
        targets = []
        for dp, dns, fns in os.walk(root):
            dns[:] = [d for d in dns if d not in SKIP_DIRS]
            targets += [os.path.join(dp, f) for f in fns]
    hits, scanned = [], 0
    for t in targets:
        if not is_scannable(t):
            continue
        scanned += 1
        hits += scan_file(t)
    secret_hits = [h for h in hits if h["category"] == "secret"]
    pii_hits = [h for h in hits if h["category"] == "pii"]
    blocking = len(secret_hits) + (len(pii_hits) if strict else 0)
    return {"root": root, "scanned": scanned, "secret_hits": secret_hits,
            "pii_hits": pii_hits, "strict": strict, "clean": not blocking,
            "blocking_count": blocking,
            "note": "SECRET hits BLOCK (credential leak). PII hits are advisory unless --strict "
                    "(a report may legitimately carry a client contact email)."}


def main():
    a = sys.argv[1:]
    if not a or a[0] in ("-h", "--help"):
        print("usage: redact.py scan <path> [--strict] | file <in> [out] | -  (stdin->stdout)")
        sys.exit(2)
    if a[0] == "scan":
        rest = [x for x in a[1:] if not x.startswith("-")]
        if not rest:
            print("usage: redact.py scan <path> [--strict]"); sys.exit(2)
        r = scan(rest[0], strict=("--strict" in a))
        print(json.dumps(r, indent=2))
        sys.exit(1 if r["blocking_count"] else 0)  # nonzero = leak = BLOCK
    if a[0] == "file":
        src = a[1]; dst = a[2] if len(a) > 2 else a[1]
        with open(src, encoding="utf-8", errors="replace") as fh:
            red, n = redact_text(fh.read())
        with open(dst, "w", encoding="utf-8") as fh:
            fh.write(red)
        print(json.dumps({"file": dst, "redactions": n}))
        return
    if a[0] == "-":
        red, n = redact_text(sys.stdin.read())
        sys.stdout.write(red)
        return
    print("unknown mode"); sys.exit(2)


if __name__ == "__main__":
    main()
