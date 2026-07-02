#!/usr/bin/env python
"""PreToolUse mutation gate — keeps AUTHENTICATED testing read-only by default.

The scope-gate hook only checks HOSTS; it lets an authenticated DELETE through as
readily as a GET (red-team blocker). This hook hard-denies state-changing
authenticated requests unless the engagement has explicitly opted in via
scope.yaml `mutation_testing: approved`.

Denies when a Bash/PowerShell command issues a mutating HTTP method
(POST/PUT/PATCH/DELETE) AND it is authenticated — i.e. it invokes auth_request.py
with --allow-mutation/--method <verb>, or curl -X <verb> carrying a Cookie/
Authorization/-b cookie. Default posture: mutations are blocked.

Also gates the **exploit-dev lane**: a command running a `.py` under a real
engagement's `exploit-dev/` directory (the exploiter's bespoke-PoC scratch) is an
active-exploitation action, so it is hard-denied unless `mutation_testing: approved`.
The PoC's target host + HTTP verbs live INSIDE the .py (invisible to a host/verb
scan), but the `exploit-dev/<...>.py` PATH is on the command line — so this path-based
check is the deterministic mechanical gate for the lane (the scaffold ALSO self-checks
scope+approval fail-closed; the committed `_template/exploit-dev/` scaffold is exempt —
it carries only a placeholder target). This is the enforcement the lane docs point to.

Contract: stdin = hook JSON. exit 0 = allow. exit 2 + stderr = deny. Fail-OPEN on
parser error (a broken gate must not brick the session), but auth_request.py AND the
exploit-dev scaffold ALSO self-enforce, so this is defense-in-depth.
"""
import sys, json, re, os

MUT = r'(?:POST|PUT|PATCH|DELETE)'

def approved():
    root = os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd())
    try:
        with open(os.path.join(root, "scope.yaml"), encoding="utf-8") as f:
            for line in f:
                m = re.match(r'\s*mutation_testing\s*:\s*(\S+)', line)
                if m:
                    return m.group(1).strip().strip('"\'').lower() in ("approved", "true", "yes")
    except Exception:
        pass
    return False

def is_auth_mutation(cmd):
    c = cmd
    # auth_request.py mutation
    if "auth_request.py" in c and (re.search(r'--allow-mutation', c) or re.search(r'--method[ =]\s*' + MUT, c, re.I)):
        return True
    # curl authenticated mutation: a mutating -X/-d AND an auth carrier
    curl_mut = re.search(r'-X\s*' + MUT, c, re.I) or (re.search(r'\bcurl\b', c) and re.search(r'(?<!\w)-d\b|--data', c))
    has_auth = re.search(r'-b\s|--cookie|(?:-H|--header)\s*["\']?\s*(Cookie|Authorization)', c, re.I)
    if re.search(r'\bcurl\b', c) and curl_mut and has_auth:
        return True
    # PowerShell-native HTTP mutation (the primary shell): Invoke-WebRequest/RestMethod / iwr / irm
    # with a mutating -Method AND an auth carrier (-Headers Authorization/Cookie / -WebSession / -Credential / -Token)
    ps_mut = re.search(r'\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b', c, re.I) and re.search(r'-Method\s+' + MUT, c, re.I)
    ps_auth = re.search(r'-Headers\b[^\n]*(?:Authorization|Cookie)|-WebSession\b|-Credential\b|-Token\b', c, re.I)
    if ps_mut and ps_auth:
        return True
    return False

def is_exploit_dev_run(cmd):
    """A command running a `.py` under a real engagement's exploit-dev/ scratch dir = the
    bespoke-PoC lane (active exploitation). The committed `_template/exploit-dev/` scaffold is
    NOT gated — it carries only a placeholder target (so py_compile / smoke tests still run)."""
    # gate the PoC even when invoked cd-first (`cd .../exploit-dev && python poc.py`): require an
    # exploit-dev path reference AND a python/.py invocation — not the two contiguous in one token.
    if not (re.search(r'exploit-dev', cmd) and re.search(r'\.py\b|\bpython\b', cmd, re.I)):
        return False
    if re.search(r'_template[\\/]exploit-dev', cmd):  # the harmless committed scaffold
        return False
    return True

def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)
    if data.get("tool_name") not in ("Bash", "PowerShell"):
        sys.exit(0)
    cmd = (data.get("tool_input") or {}).get("command", "")
    if not cmd:
        sys.exit(0)
    if not approved():
        if is_auth_mutation(cmd):
            sys.stderr.write(
                "[mutation-gate] DENIED: authenticated state-changing request (POST/PUT/PATCH/DELETE) "
                "while mutation_testing is not approved. Authenticated testing is READ-ONLY by default. "
                "If the engagement contract authorizes write testing against TEST accounts, set "
                "`mutation_testing: approved` in scope.yaml (record it in authorization.md) and retry.\n")
            sys.exit(2)
        if is_exploit_dev_run(cmd):
            sys.stderr.write(
                "[mutation-gate] DENIED: running a bespoke exploit-dev PoC while mutation_testing is not "
                "approved. The exploit-dev lane is active exploitation — off by default. If the engagement "
                "authorizes it, set `mutation_testing: approved` in scope.yaml (record the basis in "
                "authorization.md) and retry.\n")
            sys.exit(2)
    sys.exit(0)

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        sys.stderr.write(f"[mutation-gate] internal error, failing open: {e}\n")
        sys.exit(0)
