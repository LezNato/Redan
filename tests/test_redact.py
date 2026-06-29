#!/usr/bin/env python
"""test_redact.py — redact.py must catch every secret class, treat PII as advisory
(not blocking) by default, scan .env/extensionless files, and converge on re-run.

This file intentionally contains synthetic secret/PII FIXTURES (no real material):
redact-allow-file  (so the toolkit's own redact scan / doctrine_lint skips it)."""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "tools", "checks"))
import redact  # noqa: E402

CHECKS = []


def rec(name, ok, detail=""):
    CHECKS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


# (label, text, the secret substring that MUST be gone after redaction)
SECRETS = [
    ("bearer header", "Authorization: Bearer abcDEF0123456789ghiJKL", "abcDEF0123456789ghiJKL"),
    ("jwt", "t=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJlX2hlcmU", "c2lnbmF0dXJlX2hlcmU"),
    ("set-cookie", "Set-Cookie: sid=supersecretsessionvalue; HttpOnly; Secure", "supersecretsessionvalue"),
    ("kv db_password (underscore prefix)", "db_password=hunter2SuperSecret", "hunter2SuperSecret"),
    ("kv MY_API_KEY", "MY_API_KEY: 1234567890abcdefSECRET", "1234567890abcdefSECRET"),
    ("aws access key", "use " + ("AKIA" + "IOSFODNN7EXAMPLE") + " for s3", "AKIA" + "IOSFODNN7EXAMPLE"),
    ("github token", "token ghp_" + "a" * 36, "ghp_" + "a" * 36),
    ("google api key", "AIza" + "b" * 35, "AIza" + "b" * 35),
    ("url credentials", "mongodb://admin:S3cr3tPass@db.host:27017", "S3cr3tPass"),
    ("pem private key", "-----BEGIN RSA PRIVATE KEY-----\nMIIabcdef\n-----END RSA PRIVATE KEY-----", "MIIabcdef"),
]

PII = [
    ("email", "Contact jane.doe@victim-corp.com for access", "jane.doe@victim-corp.com"),
    ("us ssn", "SSN 123-45-6789 on file", "123-45-6789"),
    ("luhn pan", "card 4111 1111 1111 1111 charged", "4111 1111 1111 1111"),
]

BENIGN = [
    "The server returned HTTP 200 in 49 ms.",
    "Found 169 endpoints across 12345 requests.",
    "jQuery version 4.17.10 detected.",
    "order_id=67890 status=complete",
]


def main():
    # secrets are redacted
    for name, text, secret in SECRETS:
        red, n = redact.redact_text(text)
        rec(f"secret redacted: {name}", n > 0 and secret not in red, red[:70])

    # PII is redacted by redact_text (evidence hygiene)
    for name, text, pii in PII:
        red, n = redact.redact_text(text)
        rec(f"pii redacted: {name}", n > 0 and pii not in red, red[:70])

    # benign text is NOT mangled (no false redactions)
    for text in BENIGN:
        red, n = redact.redact_text(text)
        rec(f"benign untouched: {text[:40]}", n == 0 and red == text)

    # convergence: redact(redact(x)) == redact(x)
    combo = "db_password=hunter2; Authorization: Bearer abcDEF0123456789ghi; jane@corp.com"
    once, _ = redact.redact_text(combo)
    twice, _ = redact.redact_text(once)
    rec("redaction converges (idempotent on re-run)", once == twice)

    # luhn discriminates
    rec("luhn accepts a valid PAN", redact._luhn_ok("4111111111111111"))
    rec("luhn rejects a non-PAN 16-digit run", not redact._luhn_ok("1234567890123456"))

    # scan-everything: a .env file IS scanned and a secret BLOCKS
    d = tempfile.mkdtemp()
    with open(os.path.join(d, ".env"), "w") as f:
        f.write("DB_PASSWORD=supersecretvalue123\n")
    with open(os.path.join(d, "id_rsa"), "w") as f:  # extensionless
        f.write("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA\n-----END OPENSSH PRIVATE KEY-----\n")
    r = redact.scan(d)
    rec("scan-all: .env / extensionless scanned", r["scanned"] >= 2, f"scanned={r['scanned']}")
    rec("scan: secret in .env BLOCKS (nonzero)", not r["clean"] and r["blocking_count"] >= 1,
        f"blocking={r['blocking_count']}")

    # PII-only is advisory by default, blocking under --strict
    d2 = tempfile.mkdtemp()
    with open(os.path.join(d2, "report.md"), "w") as f:
        f.write("# Report\nClient contact: jane.doe@victim-corp.com\n")
    r2 = redact.scan(d2)
    rec("scan: PII-only does NOT block by default", r2["clean"] and len(r2["pii_hits"]) >= 1)
    r3 = redact.scan(d2, strict=True)
    rec("scan --strict: PII blocks", not r3["clean"] and r3["blocking_count"] >= 1)

    # binary is skipped, text/extensionless/.env is scanned (use REAL files —
    # is_scannable also size-checks, so a missing path is correctly unscannable)
    d3 = tempfile.mkdtemp()
    paths = {}
    for fn in ("x.env", "id_rsa", "shot.png"):
        p = os.path.join(d3, fn)
        with open(p, "w") as f:
            f.write("x")
        paths[fn] = p
    rec("is_scannable: .env yes / extensionless yes / .png no",
        redact.is_scannable(paths["x.env"]) and redact.is_scannable(paths["id_rsa"])
        and not redact.is_scannable(paths["shot.png"]))

    # regression: a real secret whose VALUE merely CONTAINS an 'xxxx' run must NOT be
    # mistaken for a placeholder — scan (the BLOCK gate) and file mode must AGREE.
    d4 = tempfile.mkdtemp()
    leaky = os.path.join(d4, "cfg.txt")
    with open(leaky, "w") as f:
        f.write("session_token=a1b2c3xxxxd4e5f6g7h8i9j0\n")
    sr = redact.scan(leaky)
    _, fn = redact.redact_text("session_token=a1b2c3xxxxd4e5f6g7h8i9j0")
    rec("scan + file AGREE on a real secret containing 'xxxx' (no false-negative)",
        (not sr["clean"]) and sr["blocking_count"] >= 1 and fn >= 1)
    # but a WHOLE-placeholder value is still skipped by scan
    ph = os.path.join(tempfile.mkdtemp(), "doc.md")
    with open(ph, "w") as f:
        f.write("API_KEY=<your-key-here>\nTOKEN=${TOKEN}\nPW=changeme\n")
    rec("scan skips whole-placeholder values (<...> / ${...} / changeme)", redact.scan(ph)["clean"])

    npass = sum(CHECKS)
    print(f"\n{npass}/{len(CHECKS)} checks passed")
    sys.exit(0 if npass == len(CHECKS) else 1)


if __name__ == "__main__":
    main()
