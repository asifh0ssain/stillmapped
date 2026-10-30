"""CI: run stillmapped on a real distro with the distro's own PHP installed.

Usage: smoke.py SOURCE [verdict]
Fails unless stillmapped finds a SOURCE build (dpkg, rpm). With 'verdict', also
fails when any of those builds resolves to unknown: on a distro with bundled
records, the real package must match one. Always fails if a running PHP
(CI starts php-fpm) isn't traced to the package that installed it.
"""

import json
import subprocess
import sys


def fail(msg):
    sys.exit(f"FAIL: {msg}")


source, need_verdict = sys.argv[1], sys.argv[2:] == ["verdict"]
p = subprocess.run([sys.executable, "-m", "stillmapped", "--json"], capture_output=True, text=True)
print(p.stdout, p.stderr, sep="\n")
if p.returncode not in (0, 1, 2):
    fail(f"exit {p.returncode}")
report = json.loads(p.stdout)
mine = [r for r in report["results"] if r["build"]["source"] == source]
if not mine:
    fail(f"no {source} build found")
untraced = [x for x in report["problems"] if "no checked build installed" in x]
if untraced:
    fail("running PHP not traced to its package: " + "; ".join(untraced))
unknown = [f"{r['build']['where']}: {r['reason']}" for r in mine if r["status"] == "unknown"]
if need_verdict and unknown:
    fail("no verdict for " + "; ".join(unknown))
print(f"ok: {len(mine)} {source} result(s), exit {p.returncode}")
