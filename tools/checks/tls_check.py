#!/usr/bin/env python
"""tls_check.py — deterministic TLS/certificate posture check (stdlib only).

Probes which TLS protocol versions a host accepts (flagging deprecated TLS 1.0/1.1),
and inspects the certificate (subject, issuer, expiry, validity). Emits JSON.

Usage: python tls_check.py <host[:port]>   (default port 443)
"""
import sys, json, ssl, socket, time, warnings, argparse

warnings.filterwarnings("ignore", category=DeprecationWarning)  # TLSv1/1.1 enum probes

UA_HOST_TIMEOUT = 12

PROTOS = [
    ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
    ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
    ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
    ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
]

def supports(host, port, ver):
    if ver is None:
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ver
        ctx.maximum_version = ver
    except (ValueError, OSError):
        return None  # this Python/OpenSSL won't even offer the version
    try:
        with socket.create_connection((host, port), timeout=UA_HOST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                return True
    except (ssl.SSLError, OSError):
        return False
    except Exception:
        return False

def get_cert(host, port):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=UA_HOST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                c = ss.getpeercert()
        cn = next((v for t in c.get("subject", []) for k, v in t if k == "commonName"), None)
        issuer = next((v for t in c.get("issuer", []) for k, v in t if k == "organizationName"), None)
        not_after = c.get("notAfter")
        days = None
        if not_after:
            days = int((ssl.cert_time_to_seconds(not_after) - time.time()) / 86400)
        return {"valid": True, "subject_cn": cn, "issuer": issuer,
                "not_after": not_after, "days_to_expiry": days}
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": f"verification failed: {e.verify_message or e}"}
    except Exception as e:
        # transport failure / handshake error / timeout / non-TLS :443 — NOT a cert-verification failure.
        # valid=None (unknown), so check() does not fabricate a 'cert-invalid' finding for an unreachable host.
        return {"valid": None, "unreachable": True, "error": str(e)}

def check(target):
    host, _, p = target.partition(":")
    port = int(p) if p else 443
    protos = {name: supports(host, port, ver) for name, ver in PROTOS}
    weak = [n for n in ("TLSv1.0", "TLSv1.1") if protos.get(n) is True]
    cert = get_cert(host, port)
    findings = []
    if weak:
        findings.append({"id": "weak-tls", "severity": "medium",
                         "detail": "deprecated protocol(s) accepted: " + ", ".join(weak)})
    if cert.get("valid") is False:
        findings.append({"id": "cert-invalid", "severity": "medium", "detail": cert.get("error")})
    elif cert.get("days_to_expiry") is not None and cert["days_to_expiry"] < 21:
        findings.append({"id": "cert-expiring", "severity": "low",
                         "detail": f"cert expires in {cert['days_to_expiry']} days"})
    return {"target": f"{host}:{port}", "ok": True, "protocols": protos,
            "weak_protocols": weak, "certificate": cert, "findings": findings}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Deterministic TLS/certificate posture check (default port 443).")
    ap.add_argument("target", metavar="host[:port]", help="target host with optional :port (default 443)")
    args = ap.parse_args()
    print(json.dumps(check(args.target), indent=2))
