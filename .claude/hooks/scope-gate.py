#!/usr/bin/env python
"""PreToolUse scope gate for the Redan toolkit.

Reads scope.yaml (a minimal, flat subset — no PyYAML needed) and HARD-DENIES
any "active" tool call (Bash/PowerShell/WebFetch/browser-navigate) that
reaches out to an out_of_scope target. With enforce_allowlist: true, it also
denies active calls to public hosts that are not in in_scope.

Contract: stdin = hook JSON {tool_name, tool_input, ...}. Exit 0 = allow.
Exit 2 + stderr = deny (reason shown to the model). Fail-OPEN on parser
errors (a broken gate must not brick the session) but log to stderr.

This is a guardrail/reminder layer, not a sandbox. The key control
is the operator only testing authorized targets. See .claude/rules/.
"""
import sys, json, re, ipaddress, os

# Tools that actually reach a target. Pure search/read tools are NOT gated
# (so research that merely mentions an excluded host isn't blocked).
GATED_EXACT = {"Bash", "PowerShell", "WebFetch"}
def is_gated(tool_name: str) -> bool:
    if tool_name in GATED_EXACT:
        return True
    t = tool_name.lower()
    return "navigate" in t  # claude-in-chrome + playwright navigate tools

# Hosts the agent may always reach: tooling, docs, vuln research, package
# registries, search. Keeps the gate from blocking normal operation even
# when enforce_allowlist is on.
INFRA_ALLOW = (
    "anthropic.com", "claude.ai", "github.com", "githubusercontent.com",
    "pypi.org", "npmjs.com", "npmjs.org", "crates.io", "go.dev",
    "google.com", "bing.com", "duckduckgo.com", "stackoverflow.com",
    "mozilla.org", "microsoft.com", "cloudflare.com", "owasp.org",
    "nvd.nist.gov", "cve.mitre.org", "mitre.org", "exploit-db.com",
    "rapid7.com", "hackerone.com", "bugcrowd.com", "portswigger.net",
)

def find_scope_file() -> str:
    root = os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd())
    return os.path.join(root, "scope.yaml")

def read_list(lines, key):
    """Return the `  - "value"` items listed directly under `key:`."""
    out, capturing = [], False
    for raw in lines:
        line = raw.rstrip("\n")
        if re.match(rf"^{re.escape(key)}\s*:", line):
            capturing = True
            continue
        if capturing:
            m = re.match(r"^\s+-\s+(.*)$", line)
            if m:
                out.append(m.group(1).strip().strip('"').strip("'"))
                continue
            # a non-list, non-blank, non-comment line ends the block
            if line.strip() and not line.lstrip().startswith("#"):
                break
    return [x for x in out if x]

def read_bool(lines, key, default=False):
    for raw in lines:
        m = re.match(rf"^{re.escape(key)}\s*:\s*(\S+)", raw)
        if m:
            return m.group(1).strip().lower() in ("true", "yes", "1", "on")
    return default

def host_matches(host, entry):
    """Does `host` match a scope entry (domain / *.wildcard / CIDR)?"""
    host = host.lower().strip(".")
    entry = entry.lower().strip()
    if "/" in entry:  # CIDR
        try:
            net = ipaddress.ip_network(entry, strict=False)
            return ipaddress.ip_address(host) in net
        except ValueError:
            return False
    if entry.startswith("*."):
        suf = entry[1:]  # ".gov"
        return host.endswith(suf)
    # bare domain: exact or subdomain
    return host == entry or host.endswith("." + entry)

def is_private(host):
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return host in ("localhost",) or host.endswith(".local")

# Extensions the bare-domain regex would otherwise misread as a TLD
# (finding_schema.py, pitfalls.md, scope.yaml, vuln_lab.js ...). A dotted
# filename in a Bash/PowerShell command is NOT a host; treating one as a host
# made enforce_allowlist deny the toolkit's OWN commands. URL-scheme and IPv4
# matches are still always treated as hosts (an explicit target). This only
# affects the bare-token heuristic, and only the denylist is safety-critical —
# no out_of_scope entry (*.gov/*.mil/*.bank/SSO domains) ends in a file ext, so
# this can never hide a denied host; it only stops file-name false positives.
FILE_EXT = {
    "md", "markdown", "rst", "py", "pyc", "pyo", "pyw", "js", "mjs", "cjs", "jsx",
    "ts", "tsx", "json", "yaml", "yml", "toml", "ini", "cfg", "conf", "lock",
    "txt", "csv", "tsv", "log", "html", "htm", "xml", "css", "scss", "sass",
    "less", "sh", "bash", "zsh", "ps1", "psm1", "psd1", "bat", "cmd", "sql",
    "db", "sqlite", "env", "example", "sample", "map", "har", "png", "jpg",
    "jpeg", "gif", "svg", "webp", "ico", "bmp", "pdf", "zip", "tar", "gz", "tgz",
    "bz2", "7z", "bak", "tmp", "old", "orig", "dist", "min", "md5", "sha1",
    "sha256", "pem", "crt", "cer", "der", "p12", "pfx", "key", "lock",
}

def extract_hosts(blob: str):
    hosts = set()
    for m in re.finditer(r"https?://([^/\s\"'`)>\]]+)", blob):
        hosts.add(m.group(1).split("@")[-1].split(":")[0])
    for m in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", blob):
        hosts.add(m.group(0))
    for m in re.finditer(r"\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})\b", blob, re.I):
        host = m.group(1)
        if host.rsplit(".", 1)[-1].lower() in FILE_EXT:   # dotted filename, not a host
            continue
        hosts.add(host)
    return {h.lower().strip(".") for h in hosts if h}

def deny(reason):
    sys.stderr.write("[scope-gate] DENIED: " + reason + "\n")
    sys.exit(2)

def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)  # no parseable input → don't block
    tool = data.get("tool_name", "")
    if not is_gated(tool):
        sys.exit(0)

    blob = json.dumps(data.get("tool_input", {}))
    hosts = extract_hosts(blob)
    if not hosts:
        sys.exit(0)

    scope = find_scope_file()
    if not os.path.exists(scope):
        sys.stderr.write("[scope-gate] no scope.yaml found — define one before active testing.\n")
        sys.exit(0)
    try:
        with open(scope, encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        sys.stderr.write(f"[scope-gate] could not read scope.yaml ({e}); failing open.\n")
        sys.exit(0)

    in_scope = read_list(lines, "in_scope")
    out_scope = read_list(lines, "out_of_scope")
    out_patterns = read_list(lines, "out_of_scope_patterns")
    enforce = read_bool(lines, "enforce_allowlist", False)

    for host in sorted(hosts):
        # 1) hard denylist — always wins
        for e in out_scope:
            if host_matches(host, e):
                deny(f"{host} matches out_of_scope entry '{e}'. Edit scope.yaml if this is wrong.")
        for p in out_patterns:
            if p.lower() in host:
                deny(f"{host} matches out_of_scope_pattern '{p}'.")
        # 2) infra / local — never gated
        if is_private(host) or any(host == a or host.endswith("." + a) for a in INFRA_ALLOW):
            continue
        # 3) optional strict allowlist
        if enforce and in_scope:
            if not any(host_matches(host, e) for e in in_scope):
                deny(f"{host} is not in in_scope and enforce_allowlist is on. Add it to scope.yaml to proceed.")
    sys.exit(0)

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:  # never brick the session on a gate bug
        sys.stderr.write(f"[scope-gate] internal error, failing open: {e}\n")
        sys.exit(0)
