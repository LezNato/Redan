#!/usr/bin/env python
"""h2_smuggle.py — HTTP/2 request-smuggling + h2c-upgrade probe (curl-based; needs curl --http2).

H2 is the 2026 CDN/origin default; the HTTP/1.1-only smuggle_probe.py CANNOT see H2.CL / H2.TE / h2c
desync. This tool probes the H2 layer:
  (1) h2c-upgrade: does the proxy upgrade an HTTP/1.1 connection via `Upgrade: h2c`? A 101 = the
      attacker can tunnel H2 over an H1 connection, bypassing front-end ACLs (CWE-444).
  (2) H2.CL timing: an H2 POST with a Content-Length anomaly (CL claims less than the body) — if the
      back-end desyncs (interprets the leftover as a new request), the timing differs from a clean
      control. Best-effort via curl -H (curl may sanitize); FULL frame-level crafting needs the Python
      `h2` library (a tools/external bootstrap, like nuclei/sqlmap).
Lead-only (timing-based; no smuggled payload). Operator-gated confirmation.

Usage: python h2_smuggle.py <url> [--probe h2c|h2cl] [--timeout 10]
"""
import sys, json, subprocess, time, argparse

def curl(args, timeout=10):
    try:
        r = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{time_total}",
                            "--max-time", str(timeout)] + args, capture_output=True, text=True, timeout=timeout + 5)
        return r.stdout.strip()
    except Exception as e:
        return f"ERR {e}"

def probe_h2c(url, timeout):
    # h2c upgrade: HTTP/1.1 with Upgrade: h2c -> 101 Switching?
    res = curl(["--http1.1", "-H", "Connection: Upgrade", "-H", "Upgrade: h2c",
                "-H", "HTTP2-Settings: ", url], timeout)
    code = res.split()[0] if res else "ERR"
    upgraded = code == "101"
    return {"probe": "h2c-upgrade", "result": res, "upgraded": upgraded,
            "findings": [{"id": "h2c-upgrade-enabled", "severity": "medium",
                          "detail": "the server/proxy accepts h2c upgrade (101) — an attacker can tunnel HTTP/2 over an HTTP/1.1 connection, bypassing front-end ACLs/inspection (CWE-444)"}] if upgraded else []}

def _last_time(s):
    """Trailing time token of a '<status> <time>' curl line; 0.0 on any error (e.g. an 'ERR ...' string)."""
    try:
        p = (s or "").split()
        return float(p[-1]) if len(p) >= 2 else 0.0
    except (ValueError, IndexError):
        return 0.0


def probe_h2cl(url, timeout):
    # H2.CL timing: H2 POST with Content-Length: 0 but a real body -> does the server desync?
    control = curl(["--http2", "-X", "POST", "-d", "control-body", url], timeout)
    cl_anom = curl(["--http2", "-X", "POST", "-H", "Content-Length: 0", "-d", "smuggle-body", url], timeout)
    # a timing/status differential suggests the server processed the anomaly differently (potential desync)
    control_t = _last_time(control)
    anom_t = _last_time(cl_anom)
    control_code = control.split()[0] if control else "ERR"
    anom_code = cl_anom.split()[0] if cl_anom else "ERR"
    suspicious = (abs(anom_t - control_t) > 2.0) or (control_code != anom_code)
    return {"probe": "h2cl-timing", "control": control, "cl_anomaly": cl_anom, "suspicious": suspicious,
            "findings": ([{"id": "h2cl-desync-suspected", "severity": "medium",
                          "detail": f"H2 CL-anomaly timing/status differs from control ({control} vs {cl_anom}) — possible H2.CL desync (CWE-444). Confirm manually; full frame-level crafting needs the Python h2 lib."}] if suspicious else []),
            "note": "best-effort via curl -H; curl may sanitize the anomaly. Full H2.CL/H2.TE crafting needs the `h2` Python library (frame-level control) — bootstrap like nuclei/sqlmap."}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="HTTP/2 smuggling + h2c-upgrade probe")
    ap.add_argument("url"); ap.add_argument("--probe", default="both", choices=["h2c", "h2cl", "both"])
    ap.add_argument("--timeout", type=int, default=10)
    a = ap.parse_args()
    out = {"target": a.url, "ok": True, "findings": []}
    if a.probe in ("h2c", "both"):
        r = probe_h2c(a.url, a.timeout); out["h2c"] = r; out["findings"] += r["findings"]
    if a.probe in ("h2cl", "both"):
        r = probe_h2cl(a.url, a.timeout); out["h2cl"] = r; out["findings"] += r["findings"]
    out["note"] = "H2-layer smuggling. h2c-upgrade is deterministic (101=yes); H2.CL is timing-best-effort (needs the h2 lib for frame-level). Lead-only — operator-gated confirmation."
    print(json.dumps(out, indent=2))
