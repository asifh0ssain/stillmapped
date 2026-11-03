"""Match installed builds against verified vendor fix records.

Policy: a build is only ever called "fixed" when a verified record for its
exact vendor, stream, package and branch says so and the version comparison
agrees, and "not affected" only when the vendor states it for that build.
Anything ambiguous resolves to "unknown", never to "fixed".
"""

import datetime
import json
import re
from importlib import resources

from .vercmp import SCHEMES, branch, compare

FIXED, NOT_FIXED, UNKNOWN, RESTART = "fixed", "not-fixed", "unknown", "restart-needed"
NOT_AFFECTED = "not-affected"  # owner, 2026-11-02: counts like fixed for the exit code
NAMES = {"php": "PHP", "openssl": "OpenSSL"}

# 'branch' is mandatory: RHEL ships several PHP branches all named "php", and
# without it an 8.3 build could be compared against an 8.2 fix and pass.
_REQUIRED = ("cve", "vendor", "stream", "package", "branch", "status", "evidence_url", "checked")


def _is_date(s):
    try:
        return datetime.date.fromisoformat(s).isoformat() == s
    except (TypeError, ValueError):
        return False


def validate_record(r):
    """Return a list of problems with one data record (empty when valid). Never
    raises: a wrong type or a bad pattern is a problem too (fuzz F3)."""
    if typed := [f"{k} must be a string" for k in (*_REQUIRED, "match", "fixed", "origin", "note", "file", "module")
                 if r.get(k) is not None and not isinstance(r[k], str)]:
        return typed  # every check below reads these fields as strings
    problems = [f"missing {k}" for k in _REQUIRED if not r.get(k)]
    status, fixed = r.get("status"), r.get("fixed")
    if status == FIXED:
        if r.get("match") not in SCHEMES:
            problems.append(f"bad match {r.get('match')!r}")
        if not fixed:
            problems.append("fixed record without a fixed version")
        elif branch(fixed) != r.get("branch") and (r.get("branch"), r.get("vendor")) != ("*", "rhel"):
            problems.append(f"fixed version {fixed} is not on branch {r.get('branch')}")
        elif fixed.endswith("-"):  # an empty release: rpm orders 1 before 1- (fuzz F8)
            problems.append(f"fixed version {fixed} has an empty release")
        # A distro fix is often backported onto an older upstream version, so a
        # rebuild with a higher version (or an epoch) would compare as newer.
        # Only the vendor's exact version format, anchored, proves the fix.
        # No "|": "^a|.*$" is anchored at both ends yet matches anything.
        if r.get("match") != "upstream" and not re.fullmatch(r"\^[^|]*\$", r.get("origin") or ""):
            problems.append("distro record needs an origin pattern anchored with ^ and $, without |")
    # The vendor's statement covers its own builds only; the origin pattern is
    # what proves a build is one. It is checked as for a fixed record (fuzz F4).
    elif status == NOT_AFFECTED and (fixed or not re.fullmatch(r"\^[^|]*\$", r.get("origin") or "")):
        problems.append("not-affected record needs an origin pattern anchored with ^ and $, without |, and no fixed version")
    elif status == UNKNOWN and not r.get("note"):
        problems.append("unknown record needs a note saying why")
    elif status not in (FIXED, NOT_AFFECTED, UNKNOWN, NOT_FIXED):
        problems.append(f"bad status {status!r}")
    if r.get("origin") is not None:
        try:  # compiled for every status; any failure, RecursionError too, is a problem (fuzz F3, F4)
            if not re.search(r["origin"], fixed or "") and fixed:
                problems.append(f"fixed version {fixed} doesn't match its own origin")
        except Exception:
            problems.append(f"bad origin pattern {r['origin']!r}")
    # A library record names the file that carries the fix: a soname, never a path.
    if r.get("module", "php") != "php" and not re.fullmatch(r"[A-Za-z0-9][\w.+-]*", r.get("file") or "", re.A):
        problems.append("library record needs a file: a soname such as libcrypto.so.3")
    if not (r.get("evidence_url") or "").startswith("https://"):
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
    records, module = [], {}
    for f in sorted((resources.files("stillmapped") / "data").iterdir(), key=lambda p: p.name):
        if not f.name.endswith(".json"):
            continue
        doc = json.loads(f.read_text(encoding="utf-8"))
        for r in doc.get("records", []):
            for cve in doc.get("cves") or [None]:
                rec = {**r, "cve": cve, "module": doc.get("module", "php")}
                problems = validate_record(rec)
                if module.setdefault(cve, rec["module"]) != rec["module"]:  # one CVE, one module
                    problems.append(f"{cve} is also in a {module[cve]} data file")
                if problems:
                    raise ValueError(f"{f.name}: {r.get('vendor')}/{r.get('package')} "
                                     f"{r.get('stream')}: {'; '.join(problems)}")
                if cves is None or cve in cves:
                    records.append(rec)
    return records


def _candidates(build, cve, records):
    hits = [r for r in records
            if (r["cve"], r["vendor"], r["package"]) == (cve, build["vendor"], build["package"])
            and r["branch"] in (build["branch"], "*") and r["stream"] in (build["stream"], "*")]
    # An exact stream record beats a wildcard one, then an exact branch beats "*" (a RHEL
    # package judged per release across rebases, owner 2026-11-03).
    hits = [r for r in hits if r["stream"] != "*"] or hits
    return [r for r in hits if r["branch"] != "*"] or hits


def trust(build):
    """The evidence a verdict rests on (Codex finding 1). Package databases and image metadata
    are trusted as installed; stillmapped does not verify package or image authenticity."""
    return ("container-pkgdb" if build["db"] == "container" else "host-pkgdb" if build["source"] in ("dpkg", "rpm")
            else "image-metadata" if build["source"] == "docker" else "root-owned-source")


def resolve_one(build, cve, records):
    base = {"cve": cve, "build": build, "record": None, "trust": trust(build)}
    hits = _candidates(build, cve, records)
    if not hits:
        return {**base, "status": UNKNOWN,
                "reason": f"no verified record for {build['vendor']} {build['stream']} "
                          f"{build['package']} ({NAMES.get(build['module'], build['module'])} {build['branch'] or '?'}); "
                          "check the vendor's advisory"}
    if len({(r["status"], r.get("match"), r.get("fixed"), r.get("origin")) for r in hits}) > 1:
        return {**base, "status": UNKNOWN,
                "reason": "bundled records disagree for this build; check the vendor's advisory"}
    rec = hits[0]
    base["record"] = rec
    if rec["status"] == NOT_FIXED:
        return {**base, "status": NOT_FIXED,
                "reason": "vendor has not published a fixed build for this stream"}
    if rec["status"] == UNKNOWN:
        return {**base, "status": UNKNOWN, "reason": rec["note"]}
    if rec["status"] == NOT_AFFECTED:
        if not re.search(rec["origin"], build["version"]):
            return {**base, "status": UNKNOWN, "reason": f"{build['version']} doesn't look like a {rec['vendor']} build; "
                                                         "can't confirm the vendor's not-affected statement covers it"}
        return {**base, "status": NOT_AFFECTED, "reason": f"{rec['vendor']} states {build['package']} "
                                                          f"{build['branch']} in {build['stream']} is not affected"}
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


def resolve_mapping(m, cve, records):
    """Verdict for a library file mapped into a process, or None when no
    record for cve names that file."""
    recs = [r for r in records if r["cve"] == cve and r.get("file") == m["file"]]
    if not recs:
        return None
    one = {**resolve_one(m["build"], cve, recs), "mapping": m}
    # Code that differs from the installed file came from some earlier version.
    return one if m["same"] else {**one, "status": RESTART, "reason": "in-memory version unknown, restart needed"}


def resolve(inventory, records, cves, strict=True):
    """strict (CVEs named): a module with no build is a problem; else only when no module has one.
    Not strict (default run, owner 2026-11-02): a CVE with no record for a build's vendor and stream
    is not judged, unless the data has no record of that module for the vendor and stream at all."""
    module = {r["cve"]: r["module"] for r in records}
    have = {k for r in records for k in ((r["cve"], r["vendor"], r["stream"]), (r["module"], r["vendor"], r["stream"]))}
    skipped = {}

    def judged(b, cve):
        known = lambda key, s: (key, b["vendor"], s) in have
        if strict or known(cve, b["stream"]) or known(cve, "*") or not (known(b["module"], b["stream"]) or known(b["module"], "*")):
            return True
        skipped.setdefault(f"{b['vendor']} {b['stream']}", set()).add(cve)
        return False

    builds = inventory["builds"]
    results = [resolve_one(b, cve, records) for b in builds for cve in cves if b["module"] == module.get(cve) and judged(b, cve)]
    results += [r for m in inventory.get("mappings", []) for cve in cves
                if (r := resolve_mapping(m, cve, records)) and judged(m["build"], cve)]
    problems, info = list(inventory.get("problems", [])), [f"{len(c)} CVEs: no vendor record for {k}, not judged" for k, c in sorted(skipped.items())]
    # Only the host's own builds count: a container must not change the host's result.
    absent = (mods := {module[c] for c in cves if c in module}) - {b["module"] for b in builds if b["db"] == "host"}
    for mod in sorted(absent):
        name, bad = "PHP" if mod == "php" else mod, strict or absent == mods
        (problems if bad else info).append(f"no {name} build found")
    limits = [f"{f}: every mapped {f.split('.so')[0]}*.so* file is checked; a copy linked statically "
              "into a program is not seen" for f in sorted({r["file"] for r in records if r["cve"] in cves and r.get("file")})]
    limits += ["PHP that no package owns is seen only while running as php, php-fpm, php-cgi, lsphp or frankenphp, or with libphp loaded."] * ("php" in mods)  # review 5 F1, F2
    stale = [w for w in inventory["workers"] if w["stale"]]
    return {"results": results, "stale_workers": stale, "problems": problems, "info": info, "limits": limits,
            "not_judged": {k: sorted(c) for k, c in sorted(skipped.items())}}


def exit_code(report):
    """0 all fixed or not affected, 1 something not fixed or needing a restart, 2 something
    unknown or part of the host not checked."""
    statuses = {r["status"] for r in report["results"]}
    if NOT_FIXED in statuses or RESTART in statuses or report["stale_workers"]:
        return 1
    if UNKNOWN in statuses or report["problems"]:
        return 2
    return 0
