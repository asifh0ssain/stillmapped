"""stillmapped command line. Read-only and offline."""

import argparse
import json
import re
import sys

from . import __version__
from .collect import _PHP_MODULE, collect
from .resolve import FIXED, NOT_AFFECTED, exit_code, load_records, resolve


def _safe(s):
    """Paths, tags and versions come from disk; keep control characters
    (terminal escape sequences) out of the terminal."""
    s = str(s)
    return s if s.isprintable() else repr(s)


def _advice(path):
    """What to restart for a PHP process on old code, by the file it maps (owner, 2026-11-04)."""
    if _PHP_MODULE.search(path):
        return "restart the web server"  # Apache, or another server with libphp loaded
    if re.search(r"/php-fpm[\d.]*( \(deleted\))?$", path):
        return "restart php-fpm"  # the master or a pool process
    return "restart this process (or the supervisor that runs it)"  # CLI, queue worker, daemon


def _table(inv, report, show_all=False):
    print(f"stillmapped {__version__}  host: {_safe(inv['os']['id'])} {_safe(inv['os']['stream'])}")
    for i in report["info"]:
        print(f"\n[INFO] {i}")
    shown = [r for r in report["results"] if show_all or r["status"] not in (FIXED, NOT_AFFECTED)]
    for r in shown:
        b = r["build"]
        print(f"\n[{r['status'].upper().replace('NOT-AFFECTED', 'NOT AFFECTED')}] {r['cve']}  {_safe(b['vendor'])}/{_safe(b['package'])} {_safe(b['version'])}")
        print(f"  from:   {_safe(b['source'])}, {_safe(b['db'])} package database ({_safe(b['where'])})")
        print(f"  trust:  {r['trust']}")
        if r.get("mapping"):
            print(f"  pid:    {r['mapping']['pid']} maps {_safe(r['mapping']['path'])}")
        print(f"  why:    {_safe(r['reason'])}")
        if r["record"]:
            print(f"  source: {r['record']['evidence_url']} (checked {r['record']['checked']})")
    print(f"\n{sum(r['status'] == FIXED for r in report['results'])} fixed")
    print(f"{sum(r['status'] == NOT_AFFECTED for r in report['results'])} not affected")
    if report["stale_workers"]:
        print(f"\n[RESTART NEEDED] {len(report['stale_workers'])} PHP process(es) still run a deleted (pre-upgrade) binary:")
        for w in report["stale_workers"]:
            print(f"  - pid {w['pid']} {_safe(w.get('name', '?'))}, {_safe(w['exe'])}: {_advice(w['exe'])}")
    if report["problems"]:
        print("\n[NOT FULLY CHECKED]")
        for p in report["problems"]:
            print(f"  - {_safe(p)}")
    for limit in report["limits"]:
        print(f"\n[SCOPE] {limit}")
    print("\nVendor data changes fast. Confirm any result against the linked advisory.")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="stillmapped",
                                 description="Is each PHP build on this host fixed for a CVE? "
                                             "Read-only, offline.")
    ap.add_argument("--cve", action="append", help="CVE id to check (repeatable; default: all bundled)")
    ap.add_argument("--json", action="store_true", help="machine-readable output (always every result)")
    ap.add_argument("--all", action="store_true", help="also list fixed results")
    ap.add_argument("--strict", action="store_true", help="a CVE not judged for a build (no vendor record) makes the result not fully checked (exit 2)")
    ap.add_argument("--version", action="version", version=f"stillmapped {__version__}")
    args = ap.parse_args(argv)

    try:
        records = load_records()
        known = {r["cve"] for r in records}
        cves = sorted(set(args.cve or known))
        missing = [c for c in cves if c not in known]
        if not cves or missing:
            print(f"stillmapped: no bundled data for {', '.join(missing) or 'any CVE'}", file=sys.stderr)
            return 3
        inv = collect(libs={r["package"]: r["module"] for r in records if r.get("file")},
                      files={r["file"]: r["module"] for r in records if r.get("file")})
        report = resolve(inv, records, cves, strict=bool(args.cve))
        if args.strict and report["not_judged"]:  # Codex finding 2
            n = sum(map(len, report["not_judged"].values()))
            report["problems"].append(f"--strict: {n} CVEs have no vendor record for a build found here and were not judged")
    except Exception as e:  # report, don't traceback, on a production host
        print(f"stillmapped: error: {_safe(e)}", file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps({"host": inv["os"], "cves": cves, **report}, indent=2))
    else:
        _table(inv, report, args.all)
    return exit_code(report)
