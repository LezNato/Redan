#!/usr/bin/env python
"""_http.py — the shared HTTP client for the deterministic checks.

Collapses the dozens of per-tool urllib fetch helpers, copied UA strings, and
copied CERT_NONE TLS contexts into one place. A probe imports get()/post() and
gets a uniform Resp(status, headers, body, url, elapsed, error) back.

Design choices (match the toolkit's posture):
  * TLS verification OFF by default (verify=False) — these probes reach
    misconfigured / self-signed targets like `curl -k`; pass verify=True to
    OBSERVE a cert/hostname problem (the auth flows do — see _authlib.ctx()).
  * HTTPError bodies are RETURNED, not raised — a 401/500 body is evidence.
  * Body reads are capped (default 200 KB) so a hostile/huge response can't OOM.
  * Egress rotation (UA pool + proxy) plugs in via _stealth HERE — this module
    is the single egress chokepoint, which is exactly where stealth belongs.

Stdlib only.

Usage:
    from _http import get, post, Resp
    r = get(url, timeout=10)            # r.status, r.text, r.headers (lower-cased), r.elapsed
    r = post(url, data=b'...', headers={"Content-Type": "application/json"})
    if r.error: ...                     # network/timeout error (status 0); never raises on HTTP status
"""
import json, os, ssl, sys, time, urllib.request, urllib.parse, urllib.error

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
MAX_BODY = 200_000

# Optional stealth layer (UA pool + proxy egress). Self-insert tools/checks/ on the
# path (the _authlib idiom) so the sibling import works even if a caller didn't;
# degrade gracefully if _stealth is absent.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from _stealth import ua as _stealth_ua, proxy as _stealth_proxy
except Exception:  # pragma: no cover - import-path dependent
    _stealth_ua = _stealth_proxy = None


def ua(rotate=False):
    """The request UA. rotate=True draws from the _stealth pool when available."""
    if rotate and _stealth_ua:
        try:
            return _stealth_ua()
        except Exception:
            pass
    return DEFAULT_UA


def context(verify=False):
    """A TLS context. verify=False = `curl -k` (CERT_NONE); verify=True = strict."""
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _headers_lower(hdrs):
    return {str(k).lower(): v for k, v in hdrs.items()}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None  # do not follow; the 30x response is returned to the caller


class Resp:
    """A uniform response. status==0 + .error set means a transport/network error."""
    __slots__ = ("status", "headers", "body", "url", "elapsed", "error")

    def __init__(self, status=0, headers=None, body=b"", url="", elapsed=0.0, error=None):
        self.status = status
        self.headers = headers or {}      # lower-cased keys
        self.body = body                  # bytes
        self.url = url                    # final URL (after any redirects)
        self.elapsed = elapsed            # seconds
        self.error = error                # str or None

    @property
    def ok(self):
        return self.error is None and 200 <= self.status < 400

    @property
    def text(self):
        return self.body.decode("utf-8", "replace")

    def json(self):
        return json.loads(self.text)

    def header(self, name, default=None):
        return self.headers.get(name.lower(), default)


def request(url, method="GET", data=None, headers=None, *, verify=False,
            timeout=20, max_body=MAX_BODY, rotate_ua=False, proxy=None,
            allow_redirects=True):
    """One HTTP request -> Resp. Never raises on an HTTP *status* (a 4xx/5xx body
    is evidence); a network/timeout/DNS error comes back as Resp(status=0, error=...)."""
    if isinstance(data, str):
        data = data.encode()
    h = {"User-Agent": ua(rotate_ua)}
    if headers:
        h.update(headers)
    ctx = context(verify)

    # proxy: explicit arg wins; else the _stealth pool/env (egress rotation)
    if proxy is None and _stealth_proxy:
        try:
            proxy = _stealth_proxy()
        except Exception:
            proxy = None

    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    if not allow_redirects:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)

    req = urllib.request.Request(url, data=data, method=method, headers=h)
    t0 = time.time()
    try:
        with opener.open(req, timeout=timeout) as r:
            body = r.read(max_body)
            status = getattr(r, "status", None) or r.getcode()
            return Resp(status, _headers_lower(dict(r.headers)), body, r.geturl(), time.time() - t0)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(max_body)
        except Exception:
            body = b""
        return Resp(e.code, _headers_lower(dict(e.headers or {})), body,
                    getattr(e, "url", url) or url, time.time() - t0)
    except Exception as ex:
        return Resp(0, {}, b"", url, time.time() - t0, error=str(ex)[:200])


def get(url, **kw):
    return request(url, method="GET", **kw)


def post(url, data=None, **kw):
    return request(url, method="POST", data=data, **kw)
