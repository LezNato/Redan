#!/usr/bin/env python
"""run_manifest.py — append-only audit trail for an engagement.

RoE requires "keep an audit trail: what was run, against what, when, and the
result." This makes it mechanical. Each tool invocation appends one JSON line to
engagements/<name>/run_manifest.jsonl (gitignored with the rest of the
engagement). When the wrapped tool emits the _result.py contract, the entry is
enriched with its tool/target/disposition.

Modes:
  wrap   run a tool, record {ts,tool,target,exit,disposition,verdict,argv}, pass
         its stdout through unchanged:
            python run_manifest.py wrap --engagement <name> -- \
                python tools/checks/nosql_probe.py https://t/api --param user
  record append an explicit entry (for non-JSON tools / manual notes):
            python run_manifest.py record --engagement <name> --tool burp \
                --target https://t --exit 0 --disposition lead --note "manual"
  show   summarize the manifest (counts by tool + disposition).

A run is reproducible from its manifest: the exact argv, when, and the verdict.
"""
import argparse, json, os, subprocess, sys, time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def manifest_path(root, engagement):
    d = os.path.join(root, engagement)
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "run_manifest.jsonl")


def append(path, entry):
    entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **entry}
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")
    return entry


def _from_tool_json(stdout):
    """Pull tool/target/disposition/verdict from a probe's JSON stdout (the
    _result.py contract), tolerating non-conforming/non-JSON output."""
    try:
        d = json.loads(stdout)
    except Exception:
        return {}
    if not isinstance(d, dict):
        return {}
    return {k: d[k] for k in ("tool", "target", "disposition", "verdict") if k in d}


def cmd_wrap(args, extra):
    if not extra:
        print("usage: run_manifest.py wrap --engagement E -- <command...>"); sys.exit(2)
    path = manifest_path(args.root, args.engagement)
    t0 = time.time()
    proc = subprocess.run(extra, capture_output=True, text=True)
    sys.stdout.write(proc.stdout)              # transparent pass-through
    if proc.stderr:
        sys.stderr.write(proc.stderr)
    entry = {"argv": extra, "exit": proc.returncode, "elapsed_s": round(time.time() - t0, 2)}
    entry.update(_from_tool_json(proc.stdout))
    append(path, entry)
    sys.exit(proc.returncode)


def cmd_record(args, _extra):
    path = manifest_path(args.root, args.engagement)
    e = append(path, {k: v for k, v in {
        "tool": args.tool, "target": args.target, "exit": args.exit,
        "disposition": args.disposition, "note": args.note}.items() if v is not None})
    print(json.dumps({"recorded": e, "manifest": path}, indent=2))


def cmd_show(args, _extra):
    path = manifest_path(args.root, args.engagement)
    if not os.path.exists(path):
        print(json.dumps({"manifest": path, "runs": 0})); return
    rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    by_tool, by_disp = {}, {}
    for r in rows:
        by_tool[r.get("tool", "?")] = by_tool.get(r.get("tool", "?"), 0) + 1
        by_disp[r.get("disposition", "n/a")] = by_disp.get(r.get("disposition", "n/a"), 0) + 1
    print(json.dumps({"manifest": path, "runs": len(rows),
                      "by_tool": by_tool, "by_disposition": by_disp,
                      "first_ts": rows[0].get("ts"), "last_ts": rows[-1].get("ts")}, indent=2))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["wrap", "record", "show"])
    ap.add_argument("--engagement", required=True)
    ap.add_argument("--root", default=os.path.join(REPO, "engagements"),
                    help="engagements root (default: <repo>/engagements)")
    ap.add_argument("--tool"); ap.add_argument("--target")
    ap.add_argument("--exit", type=int); ap.add_argument("--disposition"); ap.add_argument("--note")
    # split argv on the first bare `--` so wrap can carry an arbitrary command
    argv = sys.argv[1:]
    extra = []
    if "--" in argv:
        i = argv.index("--"); argv, extra = argv[:i], argv[i + 1:]
    args = ap.parse_args(argv)
    {"wrap": cmd_wrap, "record": cmd_record, "show": cmd_show}[args.mode](args, extra)


if __name__ == "__main__":
    main()
