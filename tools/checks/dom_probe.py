#!/usr/bin/env python
"""dom_probe.py — client-side (DOM) attack-surface battery via Playwright.

The client-side half of the flagship classes that the urllib probes can't reach:
`xss_scan.py` is server-reflection-grade; `browser_probe.py --dom` only enumerates;
`proto_pollute.py` is server-side. SPAs push these bugs into the browser, where the
value flows source -> sink entirely client-side. This tool INSTRUMENTS the DOM
(hooks the dangerous sinks BEFORE page scripts run) so a taint is OBSERVED, not
inferred. Three modes (all run by default; select with the flags):

  --xss          DOM-based XSS (WSTG-CLNT-01, CWE-79). Hooks innerHTML/outerHTML/
                 document.write/eval/setTimeout(string); drives a marked payload
                 through DOM SOURCES (location.hash, location.search params); a
                 marked value reaching a sink = taint LEAD; a real alert() dialog
                 firing = execution OBSERVED (the strongest DOM signal).
  --postmessage  Web Messaging (WSTG-CLNT-11). Wraps addEventListener('message')
                 before page load (listeners are otherwise non-enumerable) and
                 static-flags a handler that references a sink pattern with no
                 event.origin GATE (a comparison/allowlist check — a bare
                 `location.origin` reference does not count) = missing-origin LEAD.
  --protopollute Client-side prototype pollution (CWE-1321). Drives
                 `?__proto__[x]=` / `constructor[prototype][x]` / hash carriers and
                 checks whether Object.prototype was polluted, against a clean
                 control load — a deterministic SOURCE detection (gadget->exec is a
                 separate, honestly-lead step).

Everything is a LEAD: a dialog proves execution in THIS headless browser, but the
verifier still confirms real attacker DELIVERY (a cross-origin postMessage source,
a hash an attacker can plant in a victim's URL). Needs playwright + chromium
(lazy-imported; the module imports clean without them for the offline smoke test).

Usage: python dom_probe.py <url> [--xss] [--postmessage] [--protopollute]
        [--query-params q,search,name,redirect,url,s] [--timeout 20000]
"""
import argparse, json, os, sys
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _result import result  # noqa: E402  (stdlib-only sibling; playwright stays lazy)

MARK = "redanTAINT7"
# The payload (a) EXECUTES if it reaches an HTML sink UNENCODED (img onerror = the canonical
# DOM-XSS proof; the alert message is MARK so we can tell OUR dialog from a benign page alert),
# and (b) the taint hook keys on a raw '<'-bearing SENTINEL, so it fires only when the value hit
# the sink unencoded — an HTML-escaped reflection (`&lt;img…`) no longer contains the sentinel,
# so a correctly-encoded sink is NOT a false taint (the encoding-neutralization discipline that
# xss_scan.py applies server-side, applied here at the DOM sink).
XSS_PAYLOAD = f"<img src=x onerror=alert('{MARK}')>"
XSS_SENTINEL = "<img src=x onerror"   # contains '<' → absent once the value is HTML-encoded
DEFAULT_QUERY_PARAMS = ["q", "search", "name", "redirect", "url", "s", "id", "lang"]
PP_KEY = "redanPP"

# --- init scripts: injected via context.add_init_script so they run BEFORE any page
# script, which is the only way to catch a source->sink flow / register handlers. ---

XSS_INIT = r"""
(() => {
  const SENT = "%SENT%";
  const tainted = v => { try { return typeof v === "string" && v.indexOf(SENT) !== -1; } catch (e) { return false; } };
  window.__redan_sinks = [];
  const push = (sink, sample) => { try { window.__redan_sinks.push({ sink, sample: String(sample).slice(0, 160) }); } catch (e) {} };
  const hookProp = (proto, prop, name) => {
    try {
      const d = Object.getOwnPropertyDescriptor(proto, prop);
      if (!d || !d.set) return;
      Object.defineProperty(proto, prop, {
        configurable: true, enumerable: d.enumerable,
        get() { return d.get.call(this); },
        set(v) { if (tainted(v)) push(name, v); return d.set.call(this, v); }
      });
    } catch (e) {}
  };
  hookProp(Element.prototype, "innerHTML", "Element.innerHTML");
  hookProp(Element.prototype, "outerHTML", "Element.outerHTML");
  try {
    ["write", "writeln"].forEach(fn => {
      const orig = document[fn] && document[fn].bind(document);
      if (orig) document[fn] = function (...a) { if (a.some(tainted)) push("document." + fn, a[0]); return orig(...a); };
    });
  } catch (e) {}
  try { const _e = window.eval; window.eval = function (s) { if (tainted(s)) push("eval", s); return _e(s); }; } catch (e) {}
  try {
    const _st = window.setTimeout;
    window.setTimeout = function (f, ...r) { if (typeof f === "string" && tainted(f)) push("setTimeout(string)", f); return _st(f, ...r); };
  } catch (e) {}
  try {
    const _si = window.setInterval;
    window.setInterval = function (f, ...r) { if (typeof f === "string" && tainted(f)) push("setInterval(string)", f); return _si(f, ...r); };
  } catch (e) {}
  try {
    const P = window.Element && Element.prototype;
    if (P && P.insertAdjacentHTML) { const o = P.insertAdjacentHTML; P.insertAdjacentHTML = function (pos, s) { if (tainted(s)) push("insertAdjacentHTML", s); return o.call(this, pos, s); }; }
  } catch (e) {}
})();
""".replace("%SENT%", XSS_SENTINEL)

PM_INIT = r"""
(() => {
  window.__redan_pm = [];
  try {
    const _add = window.addEventListener;
    window.addEventListener = function (type, fn, ...rest) {
      if (type === "message" && fn) { try { window.__redan_pm.push((fn.toString ? fn.toString() : String(fn)).slice(0, 600)); } catch (e) {} }
      return _add.call(this, type, fn, ...rest);
    };
  } catch (e) {}
  try {
    Object.defineProperty(window, "onmessage", {
      configurable: true,
      set(f) { if (f) { try { window.__redan_pm.push((f.toString ? f.toString() : String(f)).slice(0, 600)); } catch (e) {} } this.__redan_onmessage = f; },
      get() { return this.__redan_onmessage; }
    });
  } catch (e) {}
})();
"""

# handler source patterns: does it GATE on the sender origin (a comparison / allowlist check —
# NOT a bare `location.origin` reference, which is a reply target, not a sender check), and does
# it reach a sink? A mere mention of `.origin` must not count as validation (else a handler that
# logs `e.origin` but never checks it — a real missing-origin XSS — is silently dropped).
import re  # noqa: E402
_ORIGIN_CHECK_RE = re.compile(
    r"origin\s*(?:===|==|!==|!=)"                                             # e.origin === "..."
    r"|(?:===|==|!==|!=)\s*[\w.$\[\]'\"]*origin"                              # "..." === e.origin
    r"|(?:indexOf|includes|startsWith|endsWith|match|test)\s*\([^)]*origin"   # allow.indexOf(e.origin)
    r"|origin\s*\.\s*(?:indexOf|includes|startsWith|endsWith|match|test)",    # e.origin.startsWith(...)
    re.I)
_SINK_RE = re.compile(
    r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function|"
    r"\.src\s*=|location\s*=|location\.href|location\.replace|localStorage|sessionStorage|"
    r"document\.cookie|\.setAttribute\s*\(", re.I)


def _sep(url):
    return "&" if "?" in url else "?"


def _run_xss(ctx, url, query_params, timeout):
    hits = []
    sources = [("location.hash", url + "#" + XSS_PAYLOAD)]
    for p in query_params:
        sources.append((f"query:{p}", f"{url}{_sep(url)}{p}={quote(XSS_PAYLOAD)}"))
    for label, nav in sources:
        pg = ctx.new_page()
        dialogs = []
        pg.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
        try:
            pg.goto(nav, wait_until="domcontentloaded", timeout=timeout)
            pg.wait_for_timeout(350)   # let onerror / async writes fire
            sinks = pg.evaluate("() => (window.__redan_sinks || []).slice(0, 6)")
        except Exception:
            sinks = []
        # only OUR alert counts as execution — a benign page alert()/confirm() carries a different
        # message and must not forge the strongest DOM signal.
        marked = [m for m in dialogs if MARK in (m or "")]
        if sinks or marked:
            hits.append({"class": "dom-xss", "source": label,
                         "sinks": [s.get("sink") for s in sinks],
                         "executed": bool(marked),
                         "detail": ("alert() fired with our marker — execution observed" if marked
                                    else "marked value reached a DOM sink UNENCODED (taint)")})
        try:
            pg.close()
        except Exception:
            pass
    return hits


def _run_postmessage(ctx, url, timeout):
    pg = ctx.new_page()
    handlers = []
    try:
        pg.goto(url, wait_until="domcontentloaded", timeout=timeout)
        pg.wait_for_timeout(300)
        handlers = pg.evaluate("() => (window.__redan_pm || []).slice(0, 10)")
    except Exception:
        handlers = []
    try:
        pg.close()
    except Exception:
        pass
    hits = []
    for src in handlers:
        has_origin_gate = bool(_ORIGIN_CHECK_RE.search(src))
        m = _SINK_RE.search(src)
        if m and not has_origin_gate:
            hits.append({"class": "postmessage", "origin_gate": False,
                         "sink": m.group(0), "handler": src[:200],
                         "detail": f"message handler references a sink pattern ({m.group(0)}) with no "
                                   f"event.origin gate (static co-occurrence — verify the data-flow and a "
                                   f"real cross-origin sender)"})
    return hits, len(handlers)


def _run_protopollute(ctx, url, timeout):
    carriers = [
        ("query __proto__", f"{url}{_sep(url)}__proto__[{PP_KEY}]=polluted"),
        ("query constructor.prototype", f"{url}{_sep(url)}constructor[prototype][{PP_KEY}]=polluted"),
        ("hash __proto__", f"{url}#__proto__[{PP_KEY}]=polluted"),
    ]
    check = "() => { try { return ({})[%r]; } catch (e) { return null; } }" % PP_KEY
    # control: a clean load must NOT already carry the key (else the page pollutes itself /
    # the key is a real property -> not attacker-controlled)
    pg = ctx.new_page()
    try:
        pg.goto(url, wait_until="domcontentloaded", timeout=timeout)
        pg.wait_for_timeout(150)
        control = pg.evaluate(check)
    except Exception:
        control = None
    finally:
        try:
            pg.close()
        except Exception:
            pass
    hits = []
    for label, nav in carriers:
        pg = ctx.new_page()
        try:
            pg.goto(nav, wait_until="domcontentloaded", timeout=timeout)
            pg.wait_for_timeout(200)
            polluted = pg.evaluate(check)
        except Exception:
            polluted = None
        finally:
            try:
                pg.close()
            except Exception:
                pass
        if polluted == "polluted" and control != "polluted":
            hits.append({"class": "proto-pollution", "carrier": label,
                         "polluted_key": PP_KEY,
                         "detail": "Object.prototype was polluted via a URL carrier (control load clean)"})
    return hits, control


def run(url, modes, query_params, timeout):
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return result("dom_probe", url, ok=False, disposition="none",
                      note="playwright not installed: pip install playwright && playwright install chromium")
    all_hits, meta = [], {}
    try:
        pw = sync_playwright().start()
    except Exception as e:
        return result("dom_probe", url, ok=False, disposition="none",
                      note="playwright/chromium unavailable (run `playwright install chromium`): " + str(e)[:200])
    try:
        b = pw.chromium.launch(headless=True, args=["--disable-blink-features=AutomationControlled"])
    except Exception as e:
        pw.stop()
        return result("dom_probe", url, ok=False, disposition="none",
                      note="chromium launch failed (run `playwright install chromium`): " + str(e)[:200])
    try:
        ctx = b.new_context(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                                       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
        if "xss" in modes:
            ctx.add_init_script(XSS_INIT)
        if "postmessage" in modes:
            ctx.add_init_script(PM_INIT)
        if "xss" in modes:
            all_hits += _run_xss(ctx, url, query_params, timeout)
        if "postmessage" in modes:
            pm_hits, n = _run_postmessage(ctx, url, timeout)
            all_hits += pm_hits
            meta["message_listeners"] = n
        if "protopollute" in modes:
            pp_hits, ctrl = _run_protopollute(ctx, url, timeout)
            all_hits += pp_hits
            meta["proto_control"] = ctrl
    finally:
        b.close()
        pw.stop()
    classes = sorted({h["class"] for h in all_hits})
    executed = any(h.get("executed") for h in all_hits)
    return result(
        "dom_probe", url, ok=True,
        disposition="lead" if all_hits else "none",
        signals=len(all_hits),
        verdict=(f"client-side leads: {', '.join(classes)}" + (" (alert fired)" if executed else "")
                 if all_hits else "no DOM-XSS / postMessage / prototype-pollution signal"),
        results=all_hits,
        note=("LEAD — a fired alert proves execution in this headless browser; the verifier "
              "still confirms real attacker DELIVERY (a plantable hash/param, a cross-origin "
              "postMessage source). Prototype-pollution SOURCE is deterministic; the gadget->"
              "execution step is a separate lead." if all_hits
              else "no marked value reached a DOM sink, no unguarded message handler, and "
                   "Object.prototype was not pollutable via a URL carrier."),
        modes=sorted(modes), **meta)


def main():
    ap = argparse.ArgumentParser(description="Client-side (DOM) attack-surface battery via Playwright")
    ap.add_argument("url")
    ap.add_argument("--xss", action="store_true", help="DOM-based XSS source->sink taint")
    ap.add_argument("--postmessage", action="store_true", help="postMessage handler origin-check analysis")
    ap.add_argument("--protopollute", action="store_true", help="client-side prototype pollution via URL carriers")
    ap.add_argument("--query-params", default=",".join(DEFAULT_QUERY_PARAMS),
                    help="comma list of query param names to drive as DOM-XSS sources")
    ap.add_argument("--timeout", type=int, default=20000)
    a = ap.parse_args()
    modes = set()
    if a.xss:
        modes.add("xss")
    if a.postmessage:
        modes.add("postmessage")
    if a.protopollute:
        modes.add("protopollute")
    if not modes:                                   # default: run the whole battery
        modes = {"xss", "postmessage", "protopollute"}
    qp = [x.strip() for x in a.query_params.split(",") if x.strip()]
    print(json.dumps(run(a.url, modes, qp, a.timeout), indent=2))


if __name__ == "__main__":
    main()
