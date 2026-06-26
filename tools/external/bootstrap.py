#!/usr/bin/env python
"""bootstrap.py — fetch the external pentest tools the wrappers shell out to.

These add depth/breadth beyond the dependency-free Python checks (and partly close
the vulnerable-component / hard-class gaps). Binaries are
NOT committed (see .gitignore) — run this once per machine:

  python tools/external/bootstrap.py            # nuclei (deterministic templates)
  python tools/external/bootstrap.py --sqlmap   # also clone sqlmap (deep SQLi)

nuclei -> tools/external/nuclei[.exe] ; sqlmap -> tools/external/sqlmap/sqlmap.py
After install, nuclei templates auto-update on first scan.
"""
import sys, os, json, platform, zipfile, tarfile, subprocess, urllib.request, ssl

HERE = os.path.dirname(os.path.abspath(__file__))
CTX = ssl.create_default_context()

def latest_asset(repo, want):
    r = json.load(urllib.request.urlopen(f"https://api.github.com/repos/{repo}/releases/latest", timeout=30, context=CTX))
    for a in r.get("assets", []):
        if all(w in a["name"] for w in want):
            return a["name"], a["browser_download_url"]
    return None, None

def get_nuclei():
    osn = {"windows": "windows", "linux": "linux", "darwin": "macOS"}.get(platform.system().lower(), "linux")
    arch = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "amd64"
    name, url = latest_asset("projectdiscovery/nuclei", [osn, arch])
    if not url:
        print("no matching nuclei asset"); return
    dest = os.path.join(HERE, name)
    print("downloading", name); urllib.request.urlretrieve(url, dest)
    def is_bin(m): return m.rsplit("/", 1)[-1] in ("nuclei", "nuclei.exe")
    if name.endswith(".zip"):                       # extract ONLY the binary (don't clobber our README/LICENSE)
        z = zipfile.ZipFile(dest)
        for m in (n for n in z.namelist() if is_bin(n)): z.extract(m, HERE)
    elif name.endswith((".tar.gz", ".tgz")):
        t = tarfile.open(dest)
        for m in (n for n in t.getmembers() if is_bin(n.name)): t.extract(m, HERE)
    print("nuclei installed; updating templates...")
    binp = os.path.join(HERE, "nuclei.exe" if osn == "windows" else "nuclei")
    try: subprocess.run([binp, "-update-templates", "-disable-update-check"], timeout=300)
    except Exception as e: print("template update:", e)

def get_sqlmap():
    dst = os.path.join(HERE, "sqlmap")
    if os.path.exists(dst):
        print("sqlmap already present"); return
    print("cloning sqlmap...")
    subprocess.run(["git", "clone", "--depth", "1", "https://github.com/sqlmapproject/sqlmap.git", dst])

if __name__ == "__main__":
    get_nuclei()
    if "--sqlmap" in sys.argv:
        get_sqlmap()
    print("done.")
