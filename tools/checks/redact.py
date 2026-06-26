#!/usr/bin/env python
"""redact.py — deterministic credential/secret redactor + tree scanner.

THE load-bearing control for authenticated testing (red-team finding: every
"redact secrets" rule was prose to an LLM with zero enforcement). Two modes:

  scan <path>   walk a file/dir, report credential-pattern hits, EXIT 1 if any
                (so the QA gate / a hook can BLOCK on a leak).
  file <in> [out]   write a redacted copy (in-place if no out).
  -             read stdin, write redacted stdout (pipe transcripts through this).

Findings must reproduce by ROLE, never by token — so live session material has no
business in evidence/findings/report. This makes that mechanical, not hopeful.
"""
import sys, os, re, json

# (label, compiled pattern, replacement). Order matters (headers before generic).
# Set-Cookie keeps the cookie NAME + attributes (Secure/HttpOnly/SameSite — often
# the finding itself) and redacts only the VALUE. Patterns avoid re-matching an
# already-[REDACTED] value so redact -> rescan converges to clean.
P = [
    ("set-cookie", re.compile(r'(?im)^(set-cookie\s*:\s*[^=;\s]+=)(?!\[REDACTED)([^;\r\n]+)'),
     r'\1[REDACTED]'),
    ("auth-header", re.compile(r'(?im)^(authorization|proxy-authorization|cookie|x-auth-token|x-api-key|x-csrf-token|x-xsrf-token)(\s*:\s*)(?!\s*\[REDACTED).+$'),
     r'\1\2[REDACTED]'),
    ("bearer", re.compile(r'(?i)\bbearer\s+(?!\[REDACTED)(?=[A-Za-z0-9._~+/\-]*[0-9._~+/\-])[A-Za-z0-9._~+/\-]{8,}=*'), 'Bearer [REDACTED]'),
    ("jwt", re.compile(r'\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}'), '[REDACTED:jwt]'),
    ("kv-secret", re.compile(r'(?i)\b(password|passwd|pwd|client_secret|access_token|refresh_token|id_token|api_key|apikey|auth_token|x-amz-security-token)\b(["\']?\s*[=:]\s*["\']?)(?!\[REDACTED)([^"\'&\s,;}]{3,})'),
     r'\1\2[REDACTED]'),
    ("cookie-pair", re.compile(r'(?i)\b(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|wordpress_logged_in_[a-f0-9]+|wordpress_sec_[a-f0-9]+|XSRF-TOKEN|csrftoken|connect\.sid)=(?!\[REDACTED)([^;\s]+)'),
     r'\1=[REDACTED]'),
]
TEXT_EXT = {".md", ".txt", ".json", ".html", ".htm", ".xml", ".yaml", ".yml",
            ".log", ".har", ".csv", ".js", ".css", ".cookie", ".session"}
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".playwright-mcp"}  # .pw-mcp scanned separately if asked

def redact_text(s):
    hits = 0
    for _, pat, repl in P:
        s, n = pat.subn(repl, s)
        hits += n
    return s, hits

def is_text(path):
    return os.path.splitext(path)[1].lower() in TEXT_EXT

def scan_file(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except Exception:
        return []
    found = []
    for i, line in enumerate(lines, 1):
        for label, pat, _ in P:
            if pat.search(line):
                found.append({"file": path, "line": i, "pattern": label})
                break
    return found

def scan(root):
    hits = []
    if os.path.isfile(root):
        targets = [root]
    else:
        targets = []
        for dp, dns, fns in os.walk(root):
            dns[:] = [d for d in dns if d not in SKIP_DIRS]
            targets += [os.path.join(dp, f) for f in fns]
    scanned = 0
    for t in targets:
        if not is_text(t):
            continue
        scanned += 1
        hits += scan_file(t)
    return {"root": root, "scanned": scanned, "hits": hits, "clean": not hits}

def main():
    a = sys.argv[1:]
    if not a or a[0] in ("-h", "--help"):
        print("usage: redact.py scan <path> | file <in> [out] | -  (stdin->stdout)"); sys.exit(2)
    if a[0] == "scan":
        if len(a) < 2:
            print("usage: redact.py scan <path>"); sys.exit(2)
        r = scan(a[1])
        print(json.dumps(r, indent=2))
        sys.exit(1 if r["hits"] else 0)   # nonzero exit = leak found = BLOCK
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
