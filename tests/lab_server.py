#!/usr/bin/env python
"""lab_server.py — a deliberately-vulnerable + benign LOCAL lab for the test suite.

Own asset, 127.0.0.1 only, daemon thread, self-teardown. It implements, for each
detection tool, a VULNERABLE endpoint (the tool's true-positive must fire) AND a
BENIGN look-alike (a plain reflector / constant responder — the tool's
false-positive MUST be rejected). The tests run the real tool CLIs against both.

This is the substrate for "every finding traces to a reproduction" applied to the
toolkit's OWN detectors: a fix is proven only when it fires on the vuln endpoint
and stays silent on the benign one.

  start_lab() -> (server, base_url)   # call server.shutdown() when done
  python tests/lab_server.py          # run standalone, prints the base URL
"""
import html as _html
import json
import re
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"


def _qval(query, *names):
    q = urllib.parse.parse_qs(query)
    for n in names:
        if n in q:
            return q[n][0]
    # fall back to the first value present
    for v in q.values():
        return v[0]
    return ""


def _fake_shell(cmd):
    """Tiny shell simulator: evaluate $((a*b)) arithmetic, honor sleep, echo args.
    A reflector that merely returns the literal input cannot produce the evaluated
    product — that asymmetry is exactly what cmd_inject relies on."""
    out = re.sub(r'\$\(\((\d+)\*(\d+)\)\)', lambda m: str(int(m.group(1)) * int(m.group(2))), cmd)
    m = re.search(r'sleep\s+(\d+)', out)
    if m:
        time.sleep(min(int(m.group(1)), 6))
    echoes = re.findall(r'echo\s+([^\s;|&`)]+)', out)
    return " ".join(echoes)


def _render_template(s):
    """Jinja-like engine: evaluate {{int*int}} and CONSUME the literal."""
    return re.sub(r'\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}',
                  lambda m: str(int(m.group(1)) * int(m.group(2))), s)


# Order 9 is alice's; its secret_note is the IDOR canary (data bob must not see).
ORDERS = {"9": {"id": 9, "owner": "alice", "secret_note": "ALICE_CANARY_7f3a"},
          "10": {"id": 10, "owner": "bob", "secret_note": "BOB_CANARY_2b9c"}}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    # ---- helpers -----------------------------------------------------------
    def _session_user(self):
        for part in self.headers.get("Cookie", "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k == "session":
                    return v
        return None

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj), ctype="application/json")

    # ---- GET ---------------------------------------------------------------
    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        path, query = p.path, p.query

        if path == "/health":
            return self._json(200, {"ok": True})

        # BENIGN reflector — echoes input verbatim (false-positive bait for
        # cmd_inject / xss_scan / ssti_probe). Real attacker input is reflected
        # but NEVER executed.
        if path == "/reflect":
            v = _qval(query, "q", "name", "host")
            return self._send(200, f"<html><body>You searched for: {v}</body></html>")

        # VULNERABLE command injection: the param is fed to a shell.
        if path == "/cmd-vuln":
            v = _qval(query, "host", "q")
            result = _fake_shell("ping -c1 " + v)
            return self._send(200, f"<html><body>ping result: {result}</body></html>")

        # VULNERABLE SSTI: the param flows into a template the engine renders.
        if path == "/ssti-vuln":
            v = _qval(query, "name", "q")
            return self._send(200, f"<html><body>Hello {_render_template(v)}</body></html>")

        # XSS sinks
        if path == "/xss-html":      # executable: raw reflection in HTML body
            v = _qval(query, "q", "name")
            return self._send(200, f"<html><body>Hi {v}</body></html>")
        if path == "/xss-textarea":  # non-executing: raw reflection inside <textarea>
            v = _qval(query, "q", "name")
            return self._send(200, f"<html><body><textarea>{v}</textarea></body></html>")
        if path == "/xss-encoded":   # non-executing: HTML-encoded reflection
            v = _qval(query, "q", "name")
            return self._send(200, f"<html><body>Hi {_html.escape(v)}</body></html>")

        # --- authenticated surface (for the IDOR 4-cell oracle) ---
        if path == "/me":            # identity endpoint; reflects the session user
            return self._json(200, {"user": self._session_user()})
        if path.startswith("/orders-secure/"):   # ownership ENFORCED -> no IDOR
            oid = path.rsplit("/", 1)[-1]
            u = self._session_user()
            if not u:
                return self._json(401, {"error": "login required"})
            if ORDERS.get(oid, {}).get("owner") != u:
                return self._json(403, {"error": "forbidden"})
            return self._json(200, ORDERS[oid])
        if path.startswith("/orders/"):           # VULNERABLE IDOR: any logged-in user
            oid = path.rsplit("/", 1)[-1]
            if not self._session_user():
                return self._json(401, {"error": "login required"})  # not public
            if oid not in ORDERS:
                return self._json(404, {"error": "not found"})       # bogus-id control
            return self._json(200, ORDERS[oid])                      # no ownership check

        return self._json(404, {"error": "not found"})

    # ---- POST --------------------------------------------------------------
    def do_POST(self):
        p = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            obj = json.loads(raw.decode("utf-8", "replace")) if raw else {}
        except Exception:
            obj = {}

        # VULNERABLE NoSQL auth: an operator OBJECT bypasses; a string is checked.
        if p.path == "/login-nosql-vuln":
            val = obj.get("username")
            if isinstance(val, dict):
                where = val.get("$where", "")
                if isinstance(where, str) and "sleep" in where:
                    time.sleep(3)
                    return self._json(200, {"authenticated": True, "via": "$where"})
                # operator object -> match-all -> authenticated + a longer doc list
                return self._json(200, {"authenticated": True,
                                        "docs": [{"u": f"user{i}"} for i in range(20)]})
            return self._json(401, {"error": "bad credentials"})

        # BENIGN auth: constant response regardless of input shape (operator object
        # treated as a literal non-match) -> no boolean/timing signal.
        if p.path == "/login-nosql-safe":
            return self._json(401, {"error": "bad credentials"})

        return self._json(404, {"error": "not found"})


def start_lab(host=HOST, port=0):
    srv = ThreadingHTTPServer((host, port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://{host}:{srv.server_address[1]}"


if __name__ == "__main__":
    srv, base = start_lab()
    print(f"lab on {base}  (Ctrl-C to stop)")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        srv.shutdown()
