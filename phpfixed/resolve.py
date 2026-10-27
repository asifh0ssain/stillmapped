"""Match installed builds against verified vendor fix records.

Policy: a build is only ever called "fixed" when a verified record for its
exact vendor, stream, package and PHP branch says so and the version
comparison agrees. Anything ambiguous resolves to "unknown", never to "fixed".
"""

import datetime
import json
import re
from importlib import resources

from .vercmp import SCHEMES, branch, compare

FIXED, NOT_FIXED, UNKNOWN = "fixed", "not-fixed", "unknown"

# 'branch' is mandatory: RHEL ships several PHP branches all named "php", and
# without it an 8.3 build could be compared against an 8.2 fix and pass.
_REQUIRED = ("cve", "vendor", "stream", "package", "branch", "status", "evidence_url", "checked")


def _is_date(s):
    try:
        return datetime.date.fromisoformat(s).isoformat() == s
    except (TypeError, ValueError):
        return False


def validate_record(r):
    """Return a list of problems with one data record (empty when valid)."""
    problems = [f"missing {k}" for k in _REQUIRED if not r.get(k)]
    status = r.get("status")
    if status == FIXED:
        if r.get("match") not in SCHEMES:
            problems.append(f"bad match {r.get('match')!r}")
        if not r.get("fixed"):
            problems.append("fixed record without a fixed version")
        elif branch(r["fixed"]) != r.get("branch"):
            problems.append(f"fixed version {r['fixed']} is not on branch {r.get('branch')}")
    elif status == UNKNOWN:
        if not r.get("note"):
            problems.append("unknown record needs a note saying why")
    elif status != NOT_FIXED:
        problems.append(f"bad status {status!r}")
    if r.get("origin") is not None:
        try:
            if r.get("fixed") and not re.search(r["origin"], r["fixed"]):
                problems.append(f"fixed version {r['fixed']} doesn't match its own origin")
        except (re.error, TypeError):
            problems.append(f"bad origin pattern {r['origin']!r}")
    if not str(r.get("evidence_url", "")).startswith("https://"):
        problems.append("evidence_url must be https")
    if not _is_date(r.get("checked")):
        problems.append("checked must be a real YYYY-MM-DD date")
    return problems


def load_records(cves=None):
    """All bundled records, one per CVE, optionally limited to given CVE ids.

    Each data file is one advisory whose "cves" are all fixed by the same
    updates. Any invalid record stops the run: bad data must never produce
    a verdict.
    """
    records = []
    for f in sorted((resources.files("phpfixed") / "data").iterdir(), key=lambda p: p.name):
        if not f.name.endswith(".json"):
            continue
        doc = json.loads(f.read_text(encoding="utf-8"))
        for r in doc.get("records", []):
            for cve in doc.get("cves") or [None]:
                rec = {**r, "cve": cve}
                problems = validate_record(rec)
                if problems:
                    raise ValueError(f"{f.name}: {r.get('vendor')}/{r.get('package')} "
                                     f"{r.get('stream')}: {'; '.join(problems)}")
                if cves is None or cve in cves:
                    records.append(rec)
    return records


def _candidates(build, cve, records):
    hits = [r for r in records
            if (r["cve"], r["vendor"], r["package"], r["branch"])
            == (cve, build["vendor"], build["package"], build["branch"])
            and r["stream"] in (build["stream"], "*")]
    # An exact stream record beats a wildcard one.
    return [r for r in hits if r["stream"] != "*"] or hits


def resolve_one(build, cve, records):
    base = {"cve": cve, "build": build, "record": None}
    hits = _candidates(build, cve, records)
    if not hits:
        return {**base, "status": UNKNOWN,
                "reason": f"no verified record for {build['vendor']} {build['stream']} "
                          f"{build['package']} (PHP {build['branch'] or '?'}); "
                          "check the vendor's advisory"}
    if len({(r["status"], r.get("match"), r.get("fixed")) for r in hits}) > 1:
        return {**base, "status": UNKNOWN,
                "reason": "bundled records disagree for this build; check the vendor's advisory"}
    rec = hits[0]
    base["record"] = rec
    if rec["status"] == NOT_FIXED:
        return {**base, "status": NOT_FIXED,
                "reason": "vendor has not published a fixed build for this stream"}
    if rec["status"] == UNKNOWN:
        return {**base, "status": UNKNOWN, "reason": rec["note"]}
    if rec["match"] != build["scheme"]:
        return {**base, "status": UNKNOWN,
                "reason": f"record uses {rec['match']} but build is {build['scheme']}"}
    try:
        cmp = compare(rec["match"], build["version"], rec["fixed"])
    except ValueError as e:
        return {**base, "status": UNKNOWN, "reason": f"unparseable version: {e}"}
    if cmp < 0:
        return {**base, "status": NOT_FIXED, "reason": f"{build['version']} < fixed {rec['fixed']}"}
    # A rebuild from another source can carry a higher version without the
    # vendor's patch; only the vendor's own version pattern proves the fix.
    if rec.get("origin") and not re.search(rec["origin"], build["version"]):
        return {**base, "status": UNKNOWN,
                "reason": f"{build['version']} doesn't look like a {rec['vendor']} build; "
                          "can't confirm it carries the fix"}
    return {**base, "status": FIXED, "reason": f"{build['version']} >= {rec['fixed']}"}


def resolve(inventory, records, cves):
    results = [resolve_one(b, cve, records) for b in inventory["builds"] for cve in cves]
    stale = [w for w in inventory["workers"] if w["stale"]]
    return {"results": results, "stale_workers": stale, "problems": inventory.get("problems", [])}


def exit_code(report):
    """0 all fixed, 1 something not fixed or stale workers, 2 something
    unknown or part of the host not checked."""
    statuses = {r["status"] for r in report["results"]}
    if NOT_FIXED in statuses or report["stale_workers"]:
        return 1
    if UNKNOWN in statuses or report["problems"]:
        return 2
    return 0
