# Security Policy

## What this covers

Vulnerabilities in **Redan's own code** — the agents, tools, hooks, or report renderer.
Not vulnerabilities in the systems you test with Redan (those belong to the system owner).

## Reporting

[GitHub Security Advisories](https://github.com/LezNato/Redan/security/advisories/new).
Include the affected file, a reproduction, and the impact.

This is a personal project on a best-effort basis — no guaranteed SLA, but reports are
taken seriously and patched when ready.

## What to report

- A tool that produces false results (a false positive shipped as a confirmed finding,
  or a false negative that misses a real vulnerability).
- A scope-gate bypass (reaching an out-of-scope host despite `scope.yaml`).
- A credential leak in the report renderer or evidence pipeline.
- RCE or path traversal in the tools themselves.
