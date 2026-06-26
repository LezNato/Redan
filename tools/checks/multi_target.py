#!/usr/bin/env python
"""multi_target.py — scale tooling: run the deterministic layer across MANY targets
concurrently → one per-target merged JSON + an aggregate roll-up.

The cost answer for enterprise scope (dozens of apps): instead of a full LLM
ensemble per app, fan the cheap/deterministic recon_sweep (and optionally nuclei +
cve_lookup with --deep) across every target at once, then let the operator point
the expensive agent ensemble only at the targets that surfaced something.

Usage:
  python multi_target.py <targets-file|host1,host2,...> [--deep] [--concurrency N]
  (targets file = one url/host per line; # comments allowed)
"""
import sys, os, json, argparse
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import recon_sweep
from _concurrency import workers
try:
    import nuclei_scan, cve_lookup
except Exception:
    nuclei_scan = cve_lookup = None

def assess(target, deep=False):
    out = {"target": target}
    try:
        out["recon"] = recon_sweep.sweep(target)
        out["finding_count"] = out["recon"].get("finding_count", 0)
    except Exception as e:
        out["error"] = str(e); out["finding_count"] = 0
        return out
    if deep and nuclei_scan and cve_lookup:
        try:
            n = nuclei_scan.scan(target if "://" in target else "http://" + target, severity="medium,high,critical")
            out["nuclei"] = {"count": n.get("count", 0), "findings": n.get("findings", [])}
            out["finding_count"] += n.get("count", 0)
        except Exception as e:
            out["nuclei_error"] = str(e)
        try:
            out["cve"] = cve_lookup.fingerprint(target if "://" in target else "http://" + target).get("findings", [])
            out["finding_count"] += len(out["cve"])
        except Exception as e:
            out["cve_error"] = str(e)
    return out

def run(targets, deep=False, conc=None):
    with ThreadPoolExecutor(max_workers=workers(cap=12, want=conc)) as ex:
        results = list(ex.map(lambda t: assess(t, deep), targets))
    ranked = sorted(results, key=lambda r: r.get("finding_count", 0), reverse=True)
    return {"ok": True, "targets": len(targets), "deep": deep,
            "summary": [{"target": r["target"], "finding_count": r.get("finding_count", 0),
                         "error": r.get("error")} for r in ranked],
            "results": ranked,
            "note": "deterministic triage across targets — point the LLM ensemble at the high-finding-count hosts first"}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("targets"); ap.add_argument("--deep", action="store_true")
    ap.add_argument("--concurrency", type=int, default=None)
    a = ap.parse_args()
    if os.path.isfile(a.targets):
        tlist = [l.strip() for l in open(a.targets, encoding="utf-8") if l.strip() and not l.startswith("#")]
    else:
        tlist = [t.strip() for t in a.targets.split(",") if t.strip()]
    print(json.dumps(run(tlist, a.deep, a.concurrency), indent=2))
