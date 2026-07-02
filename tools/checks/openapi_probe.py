#!/usr/bin/env python
"""openapi_probe.py — OpenAPI/Swagger spec-driven fuzzer (Schemathesis/RESTler style).

Fetches an OpenAPI/Swagger spec (from a spec URL OR a base URL by trying the
common paths), parses it, then per declared operation (path x method) sends
type-valid + type-INVALID requests and diffs each response against that
operation's baseline. Surfaces LEADS — 500 on type-confusion, 2xx on
missing-required, body-len deltas, leaked stack/internal-path/framework text —
for the agent to interpret. Emits no findings[].

Usage: python openapi_probe.py <spec-url-or-base> [--concurrency 6]
       [--max-ops 50] [--timeout 15]
"""
import argparse, json, ssl, re, string, random, hashlib
import urllib.request, urllib.parse, urllib.error
import concurrent.futures

UA = "Mozilla/5.0 (compatible; OpenApiProbe/1.0)"

SPEC_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/v3/api-docs",
    "/api-docs",
    "/api-docs.json",
    "/api/openapi.json",
    "/v1/api-docs",
    "/v2/api-docs",
]

# signals that suggest a leaked internal detail (stack trace / path / framework)
LEAK_RE = re.compile(
    r"(?i)(traceback|exception|stack\s*trace|at\s+[a-z]+\.[a-z]+\([a-z0-9_]+\.java:\d+\)|"
    r"/usr/(local/)?(bin|lib|src|share)/|c:\\\\(users|program|windows)|"
    r"org\.springframework|javax\.servlet|django\.core|flask\.|"
    r"NullPointerException|SQLException|ORA-\d{5}|PG::\w+|MySQLdb|pymysql|"
    r"<title>Whoops|internal server error|unhandled|Debug\b)"
)

# random sentinel value used to compare against a benign baseline (FP guard)
RAND_TOKEN = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))


def _hash_body(body):
    """Stable content hash of a response body (None-safe). Used by classify() to
    detect divergence even when status + length happen to coincide."""
    if body is None:
        return None
    return hashlib.sha1(body.encode("utf-8", "replace")).hexdigest()


def _ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def http_send(method, url, headers=None, body=None, timeout=15, ctx=None):
    """Send a single request; return (status, body_str, err)."""
    headers = headers or {}
    headers.setdefault("User-Agent", UA)
    data = None
    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode()
            headers.setdefault("Content-Type", "application/json")
        elif isinstance(body, bytes):
            data = body
        else:
            data = str(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx or _ctx()) as r:
            raw = r.read(200000)
            return r.status, raw.decode("utf-8", "replace"), None
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(200000)
        except Exception:
            raw = b""
        return e.code, raw.decode("utf-8", "replace"), None
    except Exception as e:
        return None, "", str(e)[:120]


def fetch_spec(target, timeout, ctx):
    """Resolve target to a parsed OpenAPI/Swagger spec dict. Returns (spec, url, err)."""
    target = target.strip().rstrip("/")
    # normalize localhost -> 127.0.0.1 (the kit convention; external tools resolve 127.0.0.1)
    target = re.sub(r"//localhost\b", "//127.0.0.1", target)
    candidates = []
    looks_spec = re.search(r"\.(json|yaml|yml)(\?|$)", target, re.I) or "/api-docs" in target.lower() or "openapi" in target.lower()
    if looks_spec:
        candidates.append(target)
    else:
        for p in SPEC_PATHS:
            candidates.append(target + p)
    for url in candidates:
        status, body, err = http_send("GET", url, timeout=timeout, ctx=ctx)
        if status and body:
            stripped = body.lstrip()
            if stripped.startswith("{"):
                try:
                    spec = json.loads(body)
                    # OpenAPI 3 or Swagger 2 look like JSON objects
                    if isinstance(spec, dict) and (
                        spec.get("openapi") or spec.get("swagger") or "paths" in spec
                    ):
                        return spec, url, None
                except ValueError:
                    pass
    return None, None, "no OpenAPI/Swagger JSON spec found at target or common paths"


def resolve_server(spec, fallback_origin):
    """Return the base URL to prefix paths with. Falls back to the target origin."""
    servers = spec.get("servers")
    if isinstance(servers, list) and servers:
        u = servers[0].get("url")
        if isinstance(u, str) and u:
            # strip trailing path template vars we can't resolve -> keep origin
            u = u.split("{")[0].rstrip("/")
            if u.startswith("http"):
                return u
            return fallback_origin.rstrip("/") + u
    # swagger v2 basePath/host
    host = spec.get("host")
    base_path = spec.get("basePath")
    if host:
        scheme = "https" if "https" in (spec.get("schemes") or ["https"]) else "http"
        return f"{scheme}://{host}{base_path or ''}".rstrip("/")
    return fallback_origin.rstrip("/")


def iter_operations(spec):
    """Yield (method_upper, path, operation_dict, parameters_list) for each declared op."""
    paths = spec.get("paths") or {}
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        # path-level params apply to all ops
        path_params = item.get("parameters") or []
        for method in ("get", "post", "put", "patch", "delete", "head", "options"):
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            op_params = list(path_params) + list(op.get("parameters") or [])
            yield method.upper(), path, op, op_params


def schema_of_param(param):
    """Return a (schema, required_flag) for a param object; handles OAS3 + Swagger2."""
    sch = param.get("schema") if isinstance(param, dict) else None
    if sch is None and isinstance(param, dict):
        # Swagger 2 inlines schema keys directly on the param
        inline = {k: param[k] for k in ("type", "format", "enum", "items") if k in param}
        sch = inline or {}
    return sch or {}


def body_schema(op):
    """Return the request-body JSON schema (OAS3) or consumes+schema (Swagger2)."""
    rb = op.get("requestBody")
    if isinstance(rb, dict):
        content = rb.get("content") or {}
        app = content.get("application/json") or {}
        return app.get("schema") or {}
    # swagger v2
    params = op.get("parameters") or []
    for p in params:
        if p.get("in") == "body":
            return p.get("schema") or {}
    return {}


def valid_value_for(schema):
    """Produce a type-valid placeholder for a leaf schema."""
    t = (schema or {}).get("type", "string")
    if t == "integer":
        return 1
    if t == "number":
        return 1.5
    if t == "boolean":
        return True
    if t == "array":
        return [valid_value_for(schema.get("items") or {})]
    if t == "object":
        return {}
    if t == "string":
        fmt = (schema or {}).get("format", "")
        if "date-time" in fmt:
            return "2025-01-01T00:00:00Z"
        if "date" in fmt:
            return "2025-01-01"
        if "uuid" in fmt:
            return "00000000-0000-0000-0000-000000000000"
        if "email" in fmt:
            return "test@example.com"
        return "test"
    return "test"


def invalid_value_for(schema):
    """Produce a type-confusion value opposite the declared type."""
    t = (schema or {}).get("type", "string")
    if t in ("integer", "number"):
        return "not_a_number"
    if t == "boolean":
        return "not_a_bool"
    if t == "array":
        return "not_an_array"
    if t == "object":
        return "not_an_object"
    return 99999  # string expected -> integer


def enum_outside_value(schema):
    """A value of the DECLARED type that is NOT in the enum (for enum-bypass).
    Stays type-correct so the probe isolates enum enforcement, not type validation."""
    sch = schema or {}
    enums = sch.get("enum") or []
    t = sch.get("type", "string")
    candidates = {
        "integer": [0, -1, 999999, len(enums) + 1],
        "number": [0.0, -1.5, 999999.5],
        "boolean": [True, False],
        "array": [[]],
        "object": [{}],
    }.get(t, [RAND_TOKEN + "_enum_bypass", "x_" + RAND_TOKEN, ""])
    for c in candidates:
        if c not in enums:
            return c
    return candidates[0]


def required_fields(schema):
    if not isinstance(schema, dict):
        return []
    props = schema.get("properties") or {}
    reqs = schema.get("required") or []
    return [k for k in reqs if k in props]


def sample_object(schema, drop=None, extra=None):
    """Build a type-valid object from a JSON schema; optionally drop/extend fields."""
    if not isinstance(schema, dict):
        schema = {}
    props = schema.get("properties") or {}
    obj = {}
    for k, sub in props.items():
        if drop and k == drop:
            continue
        obj[k] = valid_value_for(sub)
    if extra:
        obj[extra] = RAND_TOKEN
    return obj


def build_path_url(base, path, op_params):
    """Substitute {path} params with valid placeholders + collect query/header/body."""
    # path params: take from op_params first
    path_subs = {}
    query = {}
    headers = {}
    body_schema_ref = None
    path_params_used = []
    for p in op_params:
        if not isinstance(p, dict):
            continue
        loc = p.get("in")
        name = p.get("name")
        sch = schema_of_param(p)
        if loc == "path":
            val = valid_value_for(sch)
            path_subs[name] = str(val)
            path_params_used.append(name)
        elif loc == "query":
            query[name] = valid_value_for(sch)
        elif loc == "header":
            headers[name] = valid_value_for(sch)
    rendered_path = path
    for k, v in path_subs.items():
        rendered_path = rendered_path.replace("{" + k + "}", urllib.parse.quote(str(v), safe=""))
    sep = "&" if "?" in base else "?"
    qs = urllib.parse.urlencode(query) if query else ""
    url = base.rstrip("/") + rendered_path
    if qs:
        url += "?" + qs
    return url, headers, rendered_path


def classify(status, body, base_status, base_len, base_hash=None):
    """Return a (signal, suspect_class) tuple for a response that diverges from baseline.

    A signal is only emitted when the response ACTUALLY diverges from the
    per-operation baseline: a different status, a body-length delta beyond the
    noise threshold, OR a content-hash difference. This suppresses false leads
    from always-200 challenge-shell / SPA baseline-identical catch-all responses.
    (The 500/error path remains divergence-implicit — a 500 is itself the
    divergence when the baseline was not 500.)
    """
    sig, suspect = None, None
    bl = len(body or "")
    delta = bl - base_len
    body_hash = _hash_body(body)
    # divergence from baseline: status differs, OR body length differs beyond
    # a small noise threshold, OR the content hash differs.
    diverges = (
        status != base_status
        or abs(delta) > 50
        or (base_hash is not None and body_hash is not None and body_hash != base_hash)
    )
    if status == 500 and base_status != 500:   # a 500 is a divergence only when the baseline wasn't already 500
        sig, suspect = "500_on_type_confusion", "validation gap / crash (CWE-20)"
    elif status and 200 <= status < 300 and base_status and base_status >= 400:
        sig, suspect = "2xx_where_baseline_blocked", "authz / validation gap"
    elif status and 200 <= status < 300 and diverges:
        sig, suspect = "2xx_on_invalid", "validation gap (accepted bad input)"
    if body and diverges and LEAK_RE.search(body):   # gate on divergence: a leak token present in the
        sig = sig or "error_leak"                    # BASELINE too (same body, no divergence) is not payload-induced
        suspect = (suspect + "; " if suspect else "") + "info disclosure: stack/internal/framework (CWE-209)"
    if abs(delta) > 500 and base_status and status and base_status == status:
        # same status, very different body -> data/authz divergence
        sig = sig or "body_divergence"
        suspect = (suspect + "; " if suspect else "") + "response diverges from baseline (authz/data leak?)"
    return sig, suspect


def run_case(method, url, headers, body, case_label, base_status, base_len, base_hash, timeout, ctx):
    status, resp_body, err = http_send(method, url, headers=headers, body=body, timeout=timeout, ctx=ctx)
    if status is None and err:
        return {"case": case_label, "status": None, "error": err, "len_delta": 0,
                "signal": None, "suspect": None}
    sig, suspect = classify(status, resp_body or "", base_status, base_len, base_hash)
    return {
        "case": case_label,
        "status": status,
        "len_delta": (len(resp_body or "") - base_len) if status else 0,
        "signal": sig,
        "suspect": suspect,
    }


def test_operation(base, method, path, op, op_params, timeout, ctx):
    """Run the baseline + fuzz cases for one operation; return list of lead dicts."""
    try:
        url, headers, rendered_path = build_path_url(base, path, op_params)
    except Exception:
        return []
    bsch = body_schema(op)
    has_body = bool(bsch and (bsch.get("properties") or bsch.get("type") == "array"))
    # --- BASELINE: a benign, type-valid request (with an extra random header to avoid any cache hit) ---
    base_headers = dict(headers)
    base_headers["X-OpenApiProbe"] = RAND_TOKEN
    base_body = sample_object(bsch) if has_body else None
    b_status, b_body, b_err = http_send(method, url, headers=base_headers, body=base_body, timeout=timeout, ctx=ctx)
    if b_status is None:
        # baseline unreachable -> no comparison possible, skip
        return []
    base_len = len(b_body or "")
    base_hash = _hash_body(b_body or "")
    leads = []
    cases = []

    def submit(label, override_url=None, override_query=None, override_body=None, drop_body_field=None,
               extra_body_field=None, omit_query=None, omit_header=None, enum_query=None, enum_value=None):
        # build a fresh variant from the baseline components
        u = override_url or url
        # query manipulation
        if override_query or omit_query or enum_query:
            parsed = urllib.parse.urlparse(u)
            q = dict(urllib.parse.parse_qsl(parsed.query))
            if override_query:
                q.update(override_query)
            if omit_query and omit_query in q:
                del q[omit_query]
            if enum_query:
                q[enum_query] = enum_value if enum_value is not None else RAND_TOKEN + "_enum_bypass"
            u = parsed._replace(query=urllib.parse.urlencode(q)).geturl()
        h = dict(headers)
        h["X-OpenApiProbe"] = RAND_TOKEN + label
        if omit_header and omit_header in h:
            del h[omit_header]
        b = override_body
        if has_body and drop_body_field:
            b = sample_object(bsch, drop=drop_body_field)
        if has_body and extra_body_field:
            b = sample_object(bsch, extra=extra_body_field)
        return (label, u, h, b)

    jobs = []

    # (a) type-confusion on the first string/numeric path/query/header param + body
    for p in op_params:
        if not isinstance(p, dict):
            continue
        sch = schema_of_param(p)
        if not sch:
            continue
        loc = p.get("in")
        name = p.get("name")
        if loc == "query":
            jobs.append(submit(f"type_confusion_query_{name}", override_query={name: invalid_value_for(sch)}))
            break
    if has_body:
        jobs.append(submit("type_confusion_body", override_body={k: ("INVALID" if isinstance(v, str) else "STR_FOR_NUM")
                                                                 for k, v in sample_object(bsch).items()} or invalid_value_for(bsch)))

    # (b) enum-bypass on the first declared enum — send a value of the DECLARED
    # type that is outside the enum, so the probe isolates enum enforcement
    # rather than also tripping type validation.
    for p in op_params:
        sch = schema_of_param(p)
        if sch.get("enum"):
            jobs.append(submit(f"enum_bypass_{p.get('name')}", enum_query=p.get("name"),
                               enum_value=enum_outside_value(sch)))
            break

    # (c) missing a required field/param
    reqs = required_fields(bsch)
    if reqs and has_body:
        jobs.append(submit(f"missing_required_body_{reqs[0]}", drop_body_field=reqs[0]))
    # iterate query-required and header-required params SEPARATELY so a
    # required header does not skip the required-query-missing case (and vice versa)
    for p in op_params:
        if isinstance(p, dict) and p.get("required") and p.get("in") == "query":
            jobs.append(submit(f"missing_required_query_{p.get('name')}", omit_query=p.get("name")))
            break
    for p in op_params:
        if isinstance(p, dict) and p.get("required") and p.get("in") == "header":
            jobs.append(submit(f"missing_required_header_{p.get('name')}", omit_header=p.get("name")))
            break

    # (d) extra undeclared field (mass-assignment surface) — POST/PUT/PATCH only
    if method in ("POST", "PUT", "PATCH") and has_body:
        jobs.append(submit("extra_undeclared_field_massassign", extra_body_field="isAdmin"))

    # (e) oversized value on a string query param / body string field
    for p in op_params:
        if isinstance(p, dict) and schema_of_param(p).get("type", "string") == "string" and p.get("in") == "query":
            jobs.append(submit(f"oversized_query_{p.get('name')}", override_query={p.get("name"): "A" * 10000}))
            break

    # run each case sequentially within the operation (per-op rate friendliness);
    # the outer ThreadPoolExecutor fans out across OPERATIONS, not cases.
    for label, u, h, b in jobs:
        res = run_case(method, u, h, b, label, b_status, base_len, base_hash, timeout, ctx)
        if res.get("signal"):
            leads.append({
                "method": method,
                "path": rendered_path,
                "case": label,
                "status": res["status"],
                "baseline_status": b_status,
                "len_delta": res["len_delta"],
                "signal": res["signal"],
                "suspect": res["suspect"],
            })
    return leads


def main():
    ap = argparse.ArgumentParser(
        description="OpenAPI/Swagger spec-driven fuzzer (Schemathesis/RESTler style). LEAD-grade diffs."
    )
    ap.add_argument("url", help="spec URL OR base URL (auto-tries /openapi.json, /swagger.json, /v3/api-docs, ...)")
    ap.add_argument("--concurrency", type=int, default=6, help="parallel operations (default 6)")
    ap.add_argument("--max-ops", type=int, default=50, help="cap operations tested (RoE-friendly; default 50)")
    ap.add_argument("--timeout", type=int, default=15, help="per-request timeout (default 15)")
    args = ap.parse_args()

    ctx = _ctx()

    spec, spec_url, err = fetch_spec(args.url, args.timeout, ctx)
    if not spec:
        print(json.dumps({
            "target": args.url, "ok": False, "spec_url": None,
            "spec_version": None, "operations_count": 0, "tested": 0,
            "results": [], "leads": [],
            "verdict": "no spec found",
            "note": err or "no OpenAPI/Swagger spec located",
        }, indent=2))
        return

    version = spec.get("openapi") or spec.get("swagger") or "unknown"

    # resolve the base URL for path prefixing
    parsed = urllib.parse.urlparse(spec_url or args.url)
    fallback_origin = f"{parsed.scheme or 'https'}://{parsed.netloc}" if parsed.netloc else args.url.rstrip("/")
    base = resolve_server(spec, fallback_origin)

    ops = list(iter_operations(spec))
    total = len(ops)
    capped = ops[: args.max_ops]

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {
            pool.submit(test_operation, base, m, p, op, params, args.timeout, ctx): (m, p)
            for (m, p, op, params) in capped
        }
        for fut in concurrent.futures.as_completed(futures):
            try:
                leads = fut.result()
            except Exception:
                leads = []
            results.extend(leads)

    verdict = "OpenAPI fuzzing complete"
    if results:
        verdict = f"LEAD — {len(results)} non-baseline response(s) worth agent review (no vuln claimed)"
    else:
        verdict = "clean — no non-baseline responses across tested operations (LEAD grade: no vuln claimed)"

    print(json.dumps({
        "target": args.url,
        "ok": True,
        "spec_url": spec_url,
        "spec_version": version,
        "operations_count": total,
        "tested": len(capped),
        "results": results,
        "leads": [r["signal"] for r in results],
        "verdict": verdict,
        "note": "per-operation diffs are LEADS, not findings. A 500-on-type-confusion / 2xx-on-missing-required "
                "/ body-len divergence / leaked stack trace is a suspect class for the agent to verify. "
                "Compared each response to that operation's benign baseline to avoid WAF/SPA catch-all false positives.",
    }, indent=2))


if __name__ == "__main__":
    main()
