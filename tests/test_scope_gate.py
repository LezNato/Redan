#!/usr/bin/env python
"""test_scope_gate.py — the scope-gate hook must deny the denylist, fail CLOSED on
a missing scope for external hosts (while still allowing infra/local), gate the
request-issuing browser tools, canonicalize obfuscated IPs, and honor the allowlist."""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
HOOK = os.path.join(REPO, ".claude", "hooks", "scope-gate.py")

CHECKS = []


def rec(name, ok, detail=""):
    CHECKS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


def scope_dir(enforce=False, with_scope=True):
    d = tempfile.mkdtemp()
    if with_scope:
        with open(os.path.join(d, "scope.yaml"), "w") as f:
            f.write('engagement:\n  name: "t"\n'
                    'in_scope:\n  - "example.com"\n'
                    'out_of_scope:\n  - "*.gov"\n  - "*.mil"\n'
                    f'enforce_allowlist: {"true" if enforce else "false"}\n')
    return d


def gate(tool_name, tool_input, project_dir):
    payload = json.dumps({"tool_name": tool_name, "tool_input": tool_input})
    env = {**os.environ, "CLAUDE_PROJECT_DIR": project_dir}
    r = subprocess.run([sys.executable, HOOK], input=payload, env=env,
                       capture_output=True, text=True, timeout=30)
    return r.returncode  # 0 = allow, 2 = deny


def main():
    present = scope_dir()
    present_enf = scope_dir(enforce=True)
    no_scope = tempfile.mkdtemp()  # contains no scope.yaml

    rec("denylist: Bash -> *.gov denied",
        gate("Bash", {"command": "curl https://evil.gov/x"}, present) == 2)
    rec("in_scope allowed (enforce off)",
        gate("Bash", {"command": "curl https://example.com/x"}, present) == 0)
    rec("fail-CLOSED: no scope.yaml -> external host denied",
        gate("Bash", {"command": "curl https://example.com/x"}, no_scope) == 2)
    rec("no scope but localhost still allowed",
        gate("Bash", {"command": "curl http://127.0.0.1:8080/x"}, no_scope) == 0)
    rec("browser network_request tool is gated (-> *.mil denied)",
        gate("mcp__plugin_playwright_playwright__browser_network_request",
             {"url": "https://evil.mil/x"}, present) == 2)
    rec("browser_evaluate tool is gated (denylist host in JS)",
        gate("mcp__plugin_playwright_playwright__browser_evaluate",
             {"function": "() => fetch('https://evil.gov/x')"}, present) == 2)
    rec("decimal-IP canonicalized to loopback -> allowed (no scope)",
        gate("Bash", {"command": "curl http://2130706433/x"}, no_scope) == 0)
    rec("enforce_allowlist: host not in in_scope denied",
        gate("Bash", {"command": "curl https://other-target.com/x"}, present_enf) == 2)
    rec("non-gated tool (Read) never blocked",
        gate("Read", {"file_path": "/notes/evil.gov.txt"}, present) == 0)

    npass = sum(CHECKS)
    print(f"\n{npass}/{len(CHECKS)} checks passed")
    sys.exit(0 if npass == len(CHECKS) else 1)


if __name__ == "__main__":
    main()
