#!/usr/bin/env python
"""oob.py — out-of-band collaborator abstraction for blind-class confirmation (stdlib core).

Blind classes (SSRF, XXE, request-smuggling, deserialization, blind SQLi, SSTI) need an OOB
callback to PROVE the server made the request / fired the payload. The kit's xxe_probe bound a
localhost-only listener with NO DNS channel -> a DNS-only-callback or egress-filtered target
reported a FALSE CLEAN. This module is the shared collaborator:

  Collab backend:
    local  (default, stdlib) — threaded HTTP listener on a random port; callback URL
           http://<this-host>:<port>/<marker>. Works for same-machine/lab targets.
    interactsh  (real targets) — bootstraps the ProjectDiscovery interactsh-client binary
           (via tools/external/bootstrap.py, like nuclei/sqlmap) -> gives a DNS+HTTP+SMTP+LDAP
           collaborator domain that survives HTTP-egress filtering. Fallback to local if absent.

  Interface (used by xxe_probe / SSRF / smuggling / deser / the exploiter agent):
    c = Collab(backend="local"|"interactsh")
    url = c.callback("marker1")      # the URL/IP to hand the target
    time.sleep(wait); hits = c.poll("marker1")   # did the target call back?
    c.stop()

Usage as a CLI smoke:  python oob.py --smoke   (starts local, prints a callback URL for 20s)
"""
import sys, os, json, time, threading, socket, http.server, socketserver, subprocess, tempfile, re

class _LocalHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.server.hits.add(self.path)
        self.send_response(200); self.send_header("Content-Type", "image/gif"); self.end_headers()
        self.wfile.write(b"GIF89a")  # tiny gif so <img>/fetch callbacks succeed
    def do_POST(self):
        self.do_GET()

class Collab:
    def __init__(self, backend="local", host=None):
        self.backend = backend if backend in ("local", "interactsh") else "local"
        self.host = host or _my_ip()
        self._httpd = None
        self._thread = None
        self._proc = None
        self._interact_domain = None
        self._tmpdir = None

    def _start_local(self):
        self._httpd = socketserver.TCPServer(("0.0.0.0", 0), _LocalHandler)
        self._httpd.hits = set()
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def _start_interactsh(self):
        # bootstrap the interactsh-client binary (like nuclei/sqlmap); fall back to local on failure
        ext = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "external")
        binp = None
        for cand in (os.path.join(ext, "interactsh-client"), os.path.join(ext, "interactsh-client.exe")):
            if os.path.exists(cand):
                binp = cand; break
        if not binp:
            return False
        self._tmpdir = tempfile.mkdtemp(prefix="oob_")
        try:
            self._proc = subprocess.Popen([binp, "-json"], cwd=self._tmpdir,
                                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            # the client prints its collaborator domain to stdout on startup
            line = self._proc.stdout.readline().decode("utf-8", "replace")
            m = re.search(r"([a-z0-9]{20,}\.[a-z0-9.\-]+)", line)
            if m:
                self._interact_domain = m.group(1); return True
        except Exception:
            pass
        return False

    def start(self):
        if self.backend == "interactsh" and self._start_interactsh():
            self._mode = "interactsh"
        else:
            self._start_local(); self._mode = "local"
        return self

    def callback(self, marker):
        if self._mode == "interactsh":
            return f"http://{marker}.{self._interact_domain}/"
        return f"http://{self.host}:{self.port}/{marker}"

    def poll(self, marker, timeout=0):
        if timeout:
            time.sleep(timeout)
        if self._mode == "interactsh":
            # read the interactsh-client stdout for interaction records mentioning the marker
            try:
                self._proc.stdout.flush()
                import select
                while select.select([self._proc.stdout], [], [], 0)[0]:
                    line = self._proc.stdout.readline().decode("utf-8", "replace")
                    if marker in line:
                        return True
            except Exception:
                pass
            return False
        return any(marker in h for h in self._httpd.hits)

    def stop(self):
        try:
            if self._httpd: self._httpd.shutdown()
            if self._proc: self._proc.terminate()
        except Exception:
            pass


def _my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80)); return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="OOB collaborator (smoke / library)")
    ap.add_argument("--smoke", action="store_true", help="start a local listener + print a callback URL for 20s")
    ap.add_argument("--backend", default="local")
    a = ap.parse_args()
    if a.smoke:
        c = Collab(a.backend).start()
        url = c.callback("smoke-test")
        print(json.dumps({"backend": c._mode, "callback_url": url, "polling_for": 20,
                          "hint": "curl/wget that URL from anywhere reaching this host to see a hit"}))
        for _ in range(20):
            if c.poll("smoke-test"):
                print(json.dumps({"hit": True})); break
            time.sleep(1)
        c.stop()
