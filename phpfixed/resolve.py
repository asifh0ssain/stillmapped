"""Match installed builds against verified vendor fix records.

Policy: a build is only ever called "fixed" when a verified record for its
exact vendor, stream and package says so and the version comparison agrees.
Anything ambiguous resolves to "unknown", never to "fixed".
"""

import json
import re
from importlib import resources

from .vercmp import SCHEMES, compare

FIXED, NOT_FIXED, UNKNOWN = "fixed", "not-fixed", "unknown"

_REQUIRED = ("vendor", "stream", "package", "match", "status", "evidence_url", "checked")
# Package names that already pin the PHP branch: php8.2, ea-php82, alt-php74.
_BRANCH_IN_NAME = re.compile(r"\d\.\d|\d\d$")


def validate_record(r):
    """Return a list of problems with one data record (empty when valid)."""
    problems = [f"missing {k}" for k in _REQUIRED if not r.get(k)]
    if not (r.get("cve") or r.get("cves")):
        problems.append("missing cve/cves")
    if r.get("status") not in (FIXED, NOT_FIXED, UNKNOWN):
        problems.append(f"bad status {r.get('status')!r}")
    if r.get("match") not in (*SCHEMES, "unresolvable"):
        problems.append(f"bad match {r.get('match')!r}")
    if r.get("status") == FIXED and r.get("match") in SCHEMES and not r.get("fixed"):
        problems.append("fixed record without a fixed version")
    # Without a branch, a php 8.3 build could be compared against an 8.2 fix
    # and wrongly pass.
    if not _BRANCH_IN_NAME.search(r.get("package", "")) and not r.get("branch"):
        problems.append("package name doesn't pin the PHP branch; set 'branch'")
    if not str(r.get("evidence_url", "")).startswith("https://"):
        problems.append("evidence_url must be https")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(r.get("checked", ""))):
        problems.append("checked must be YYYY-MM-DD")
    return problems


def load_records(cves=None):
    """All bundled records, one per CVE, optionally limited to given CVE ids.

    A record may list several CVEs fixed by the same update under "cves".
    """
    records = []
    data = resources.files("phpfixed") / "data"
    if not data.is_dir():
        return records
    for f in sorted(data.iterdir(), key=lambda p: p.name):
        if not f.name.endswith(".json"):
            continue
        doc = json.loads(f.read_text(encoding="utf-8"))
        for r in doc.get("records", []):
            for cve in r.get("cves") or [r.get("cve")]:
                if cves is None or cve in cves:
                    records.append({**r, "cve": cve})
    return records


def _candidates(build, cve, records):
    hits = [r for r in records
            if r["cve"] == cve and r["vendor"] == build["vendor"]
            and r["package"] == build["package"]
            and r["stream"] in (build["stream"], "*")
            and r.get("branch") in (None, build["branch"])]
    # An exact stream record beats a wildcard one.
    return sorted(hits, key=lambda r: r["stream"] == "*")


def resolve_one(build, cve, records):
    base = {"cve": cve, "build": build, "record": None}
    hits = _candidates(build, cve, records)
    if not hits:
        return {**base, "status": UNKNOWN,
                "reason": f"no verified record for {build['vendor']} {build['stream']} "
                          f"{build['package']}; check the vendor's advisory"}
    rec = hits[0]
    base["record"] = rec
    if rec["status"] == NOT_FIXED:
        return {**base, "status": NOT_FIXED,
                "reason": "vendor has not published a fixed build for this stream"}
    if rec["status"] != FIXED or rec["match"] == "unresolvable" or not rec.get("fixed"):
        return {**base, "status": UNKNOWN,
                "reason": rec.get("note") or "fix state can't be read from the version string"}
    if rec["match"] != build["scheme"]:
        return {**base, "status": UNKNOWN,
                "reason": f"record uses {rec['match']} but build is {build['scheme']}"}
    try:
        cmp = compare(rec["match"], build["version"], rec["fixed"])
    except ValueError as e:
        return {**base, "status": UNKNOWN, "reason": f"unparseable version: {e}"}
    if cmp >= 0:
        return {**base, "status": FIXED, "reason": f"{build['version']} >= {rec['fixed']}"}
    return {**base, "status": NOT_FIXED, "reason": f"{build['version']} < fixed {rec['fixed']}"}


def resolve(inventory, records, cves):
    results = [resolve_one(b, cve, records) for b in inventory["builds"] for cve in cves]
    stale = [w for w in inventory["workers"] if w["stale"]]
    return {"results": results, "stale_workers": stale}


def exit_code(report):
    """0 all fixed, 1 something not fixed or stale workers, 2 something unknown."""
    statuses = {r["status"] for r in report["results"]}
    if NOT_FIXED in statuses or report["stale_workers"]:
        return 1
    if UNKNOWN in statuses:
        return 2
    return 0
