# External tools

Established pentest tools the deterministic-check wrappers shell out to, for
depth/breadth beyond the dependency-free Python checks. **Binaries are NOT
committed** (gitignored) — install per machine:

```bash
python tools/external/bootstrap.py            # nuclei
python tools/external/bootstrap.py --sqlmap   # + sqlmap
```

| Tool | What | Wrapper |
|---|---|---|
| **nuclei** (ProjectDiscovery, single binary) | thousands of DETERMINISTIC templates — CVEs, exposures, misconfig, default-logins, takeovers. Doesn't vary by model. | `tools/checks/nuclei_scan.py` |
| **sqlmap** (pure Python) | deep SQLi confirmation + DBMS characterization (no data dump) | `tools/checks/sqlmap_run.py` |

These deliberately **end the "dependency-free pure-Python" purity** — the right
call for enterprise depth (you ship these tools). They are ACTIVE and can be noisy:
rate-limited by default, in-scope hosts only (the calling agent enforces scope),
and a nuclei `version→CVE` hit is a **lead** until the verifier shows exploitability.

`bootstrap.py` extracts only the nuclei binary (not its bundled README/LICENSE).
The external resolvers don't know `localhost` — the wrappers normalize to `127.0.0.1`.
After install, nuclei templates auto-update; if a scan says "no templates", run
`tools/external/nuclei.exe -update-templates` (or `git clone` the
`projectdiscovery/nuclei-templates` repo into the path nuclei reports).

Not bootstrapped (separate install required): **ZAP** (needs Java) and reliable
**deserialization exploitation** (needs ysoserial/Java or phpggc).
