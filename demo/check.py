"""Checks phpfixed's verdict in deb.sh. Args: exit code, expected exit, pid, JSON file.

stale (expected 1): the package is fixed, and the pid that mapped libcrypto
before the upgrade is "in-memory version unknown, restart needed".
thirdparty (expected 2): a higher version that isn't Debian's build is
unknown, and nothing reads fixed.
"""
import json
import sys

rc, want, pid, path = sys.argv[1:]
rows = json.load(open(path))["results"]
pkg = [x["status"] for x in rows if not x.get("mapping")]
if want == "1":
    mine = [x for x in rows if (x.get("mapping") or {}).get("pid") == pid]
    ok = (pkg == ["fixed"] and [x["status"] for x in mine] == ["restart-needed"]
          and mine[0]["mapping"]["path"].endswith("libcrypto.so.3 (deleted)")
          and mine[0]["reason"] == "in-memory version unknown, restart needed")
else:
    ok = pkg == ["unknown"] and "fixed" not in {x["status"] for x in rows}
print(f"CHECK exit {want} and expected verdicts:", "PASS" if ok and rc == want else "FAIL")
