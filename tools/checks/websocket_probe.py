#!/usr/bin/env python
"""websocket_probe.py — WebSocket / stateful-surface probe (stdlib only, raw socket).

Modern SPAs (collab/trading/realtime) put most attack surface on ws://|wss:// — message-level
IDOR, handshake authz (Origin/cookie/subprotocol), unauthenticated broadcast channels. The kit had
zero WS coverage. This does the WS handshake (testing auth) + a send/receive, stdlib raw socket.

Tests: (1) handshake reachability + the 101 response; (2) handshake AUTH — does it accept an
arbitrary Origin / no-cookie / a spoofed subprotocol? (a missing-401 handshake = unauth reach);
(3) a basic send/receive (echo / a recorded message). Full 2-session message-level IDOR / subscription
isolation needs the auth-tester paired sessions (note).

Usage: python websocket_probe.py <ws-url> [--origin <o>] [--cookie <c>] [--subprotocol <s>] [--message <m>] [--auth-header "Authorization: Bearer ..."]
"""
import sys, json, base64, ssl, socket, argparse, os

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

def _frame_encode(payload, opcode=0x1):
    b = payload.encode() if isinstance(payload, str) else payload
    mask = os.urandom(4)
    h = bytes([0x80 | opcode])
    n = len(b)
    if n < 126: h += bytes([0x80 | n])
    elif n < 65536: h += bytes([0x80 | 126]) + n.to_bytes(2, "big")
    else: h += bytes([0x80 | 127]) + n.to_bytes(8, "big")
    return h + bytes(c ^ m for c, m in zip(b, mask * n))

def _frame_decode(sock):
    hdr = sock.recv(2)
    if len(hdr) < 2: return None, None
    opcode = hdr[0] & 0x0f; masked = bool(hdr[1] & 0x80); ln = hdr[1] & 0x7f
    if ln == 126: ln = int.from_bytes(sock.recv(2), "big")
    elif ln == 127: ln = int.from_bytes(sock.recv(8), "big")
    mask = sock.recv(4) if masked else b""
    data = b""
    while len(data) < ln:
        chunk = sock.recv(ln - len(data));
        if not chunk: break
        data += chunk
    if masked: data = bytes(c ^ m for c, m in zip(data, mask * ln))
    return opcode, data.decode("utf-8", "replace")

def probe(ws_url, origin, cookie, subprotocol, message, auth_header):
    from urllib.parse import urlparse
    u = urlparse(ws_url)
    tls = u.scheme.lower() == "wss"
    host = u.hostname; port = u.port or (443 if tls else 80); path = u.path or "/"
    if u.query: path += "?" + u.query
    key = base64.b64encode(os.urandom(16)).decode()
    lines = [f"GET {path} HTTP/1.1", f"Host: {host}:{port}", "Upgrade: websocket",
             "Connection: Upgrade", f"Sec-WebSocket-Key: {key}", "Sec-WebSocket-Version: 13",
             f"User-Agent: {UA}"]
    if origin: lines.append(f"Origin: {origin}")
    if cookie: lines.append(f"Cookie: {cookie}")
    if auth_header: lines.append(auth_header)
    if subprotocol: lines.append(f"Sec-WebSocket-Protocol: {subprotocol}")
    req = ("\r\n".join(lines) + "\r\n\r\n").encode()
    out = {"target": ws_url, "ok": True, "tls": tls, "host": f"{host}:{port}", "path": path, "findings": []}
    try:
        raw = socket.create_connection((host, port), timeout=12)
        sock = (ssl.create_default_context().wrap_socket(raw, server_hostname=host)
                if tls else raw)
        sock.sendall(req)
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = sock.recv(4096)
            if not chunk: break
            resp += chunk
        head = resp.split(b"\r\n\r\n", 1)[0].decode("utf-8", "replace")
        out["handshake_response_head"] = head[:300]
        out["handshake_101"] = "101" in head.split("\r\n")[0]
        # handshake-auth test: did it accept an arbitrary Origin / no-auth?
        if (origin or auth_header) and out["handshake_101"]:
            out["findings"].append({"id": "ws-handshake-permissive", "severity": "medium",
                "detail": f"WS handshake SUCCEEDED with a spoofed {'Origin' if origin else 'Authorization'} ({origin or auth_header}) — handshake authz is weak (CWE-306); test message-level access next"})
        if not out["handshake_101"]:
            out["findings"].append({"id": "ws-handshake-rejected", "severity": "info",
                "detail": "WS handshake rejected — " + head.split("\r\n")[0]})
            return out
        # send/receive one frame
        if message:
            sock.sendall(_frame_encode(message))
            sock.settimeout(4)
            try:
                op, data = _frame_decode(sock)
                out["echo_or_response"] = (data or "")[:400]
            except Exception as e:
                out["echo_error"] = str(e)[:100]
        sock.close()
    except Exception as e:
        out["error"] = str(e)[:160]; out["ok"] = False
    out["note"] = "WS stateful surface. Handshake-auth + a basic send/receive here; 2-session message-level IDOR / subscription isolation needs the auth-tester paired sessions."
    return out

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="WebSocket / stateful-surface probe")
    ap.add_argument("url"); ap.add_argument("--origin"); ap.add_argument("--cookie"); ap.add_argument("--subprotocol")
    ap.add_argument("--message", default="probe-test"); ap.add_argument("--auth-header")
    a = ap.parse_args()
    print(json.dumps(probe(a.url, a.origin, a.cookie, a.subprotocol, a.message, a.auth_header), indent=2))
