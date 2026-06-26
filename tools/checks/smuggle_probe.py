#!/usr/bin/env python
"""smuggle_probe.py — HTTP request-smuggling / desync DETECTION (timing-based, safe).

Sends the canonical CL.TE and TE.CL *timing* probes (PortSwigger technique): a
desync makes the back-end wait for bytes that never arrive, so a vulnerable chain
times out while a control returns promptly. This sends NO malicious smuggled
request — detection only; it never injects a payload that could affect another
user (RoE). A hit is a LEAD: confirming/exploiting desync is an operator-gated
manual step.

Needs a front-end/back-end chain (proxy/LB/CDN) to be vulnerable — a single
origin server can't desync, so "not detected" against one is expected.

Usage:
  python smuggle_probe.py <url> [--timeout 6]
"""
import sys, re, json, ssl, time, socket, argparse
from urllib.parse import urlparse

def send_raw(host, port, use_tls, payload, timeout=6):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except Exception as e:
        return None, True, str(e)
    if use_tls:
        try:
            s = ssl._create_unverified_context().wrap_socket(s, server_hostname=host)
        except Exception as e:
            s.close(); return None, True, str(e)
    t = time.perf_counter()
    try:
        s.sendall(payload.encode("latin-1"))
        s.settimeout(timeout)
        data = b""
        while len(data) < 2048:
            chunk = s.recv(1024)
            if not chunk:
                break
            data += chunk
        return round((time.perf_counter() - t) * 1000), False, data[:200].decode("latin-1", "replace")
    except socket.timeout:
        return round((time.perf_counter() - t) * 1000), True, "timeout"
    except Exception as e:
        return round((time.perf_counter() - t) * 1000), False, str(e)
    finally:
        try: s.close()
        except Exception: pass

def probe(url, timeout=6):
    u = urlparse(url if "://" in url else "http://" + url)
    host = u.hostname; use_tls = (u.scheme == "https")
    port = u.port or (443 if use_tls else 80)
    path = u.path or "/"
    H = f"Host: {host}"
    control = (f"GET {path} HTTP/1.1\r\n{H}\r\nConnection: close\r\n\r\n")
    clte = (f"POST {path} HTTP/1.1\r\n{H}\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n"
            f"Connection: close\r\n\r\n1\r\nA\r\nX")
    tecl = (f"POST {path} HTTP/1.1\r\n{H}\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n"
            f"Connection: close\r\n\r\n0\r\n\r\nX")
    base_ms, base_to, _ = send_raw(host, port, use_tls, control, timeout)
    if base_ms is None:
        return {"target": url, "ok": False, "error": "could not connect"}
    results, findings = [], []
    for name, payload in (("CL.TE", clte), ("TE.CL", tecl)):
        ms, to, _ = send_raw(host, port, use_tls, payload, timeout)
        # a probe that times out while the control returned promptly => desync lead
        suspicious = bool(to and not base_to and (ms or 0) > max(2500, (base_ms or 0) * 3))
        results.append({"variant": name, "ms": ms, "timed_out": to, "suspicious": suspicious})
        if suspicious:
            findings.append({"id": "http-request-smuggling", "severity": "high", "cwe": "CWE-444",
                             "location": url,
                             "detail": f"{name} desync timing signature (probe timed out at {ms}ms vs control {base_ms}ms) "
                                       f"— LEAD: confirm manually before any exploitation (operator-gated)"})
    return {"target": url, "ok": True, "control_ms": base_ms, "results": results, "findings": findings,
            "note": "timing detection only; no smuggled payload sent. Needs a proxy/back-end chain to be vulnerable."}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("url"); ap.add_argument("--timeout", type=int, default=6)
    a = ap.parse_args()
    print(json.dumps(probe(a.url, a.timeout), indent=2))
