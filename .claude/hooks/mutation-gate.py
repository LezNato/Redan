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

Contract: stdin = hook JSON. exit 0 = allow. exit 2 + stderr = deny. Fail-OPEN on
parser error (a broken gate must not brick the session), but the auth_request.py
tool ALSO self-enforces the allowlist, so this is defense-in-depth.
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
    has_auth = re.search(r'-b\s|--cookie|-H\s*["\']?\s*(Cookie|Authorization)', c, re.I)
    if re.search(r'\bcurl\b', c) and curl_mut and has_auth:
        return True
    return False

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
    if is_auth_mutation(cmd) and not approved():
        sys.stderr.write(
            "[mutation-gate] DENIED: authenticated state-changing request (POST/PUT/PATCH/DELETE) "
            "while mutation_testing is not approved. Authenticated testing is READ-ONLY by default. "
            "If the engagement contract authorizes write testing against TEST accounts, set "
            "`mutation_testing: approved` in scope.yaml (record it in authorization.md) and retry.\n")
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
