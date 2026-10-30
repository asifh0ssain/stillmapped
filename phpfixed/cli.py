"""phpfixed command line. Read-only and offline."""

import argparse
import json
import sys

from . import __version__
from .collect import collect
from .resolve import FIXED, exit_code, load_records, resolve


def _safe(s):
    """Paths, tags and versions come from disk; keep control characters
    (terminal escape sequences) out of the terminal."""
    s = str(s)
    return s if s.isprintable() else repr(s)


def _table(inv, report, show_all=False):
    print(f"phpfixed {__version__}  host: {_safe(inv['os']['id'])} {_safe(inv['os']['stream'])}")
    for i in report["info"]:
        print(f"\n[INFO] {i}")
    shown = [r for r in report["results"] if show_all or r["status"] != FIXED]
    for r in shown:
        b = r["build"]
        print(f"\n[{r['status'].upper()}] {r['cve']}  {_safe(b['vendor'])}/{_safe(b['package'])} {_safe(b['version'])}")
        print(f"  from:   {_safe(b['source'])}, {_safe(b['db'])} package database ({_safe(b['where'])})")
        if r.get("mapping"):
            print(f"  pid:    {r['mapping']['pid']} maps {_safe(r['mapping']['path'])}")
        print(f"  why:    {_safe(r['reason'])}")
        if r["record"]:
            print(f"  source: {r['record']['evidence_url']} (checked {r['record']['checked']})")
    print(f"\n{sum(r['status'] == FIXED for r in report['results'])} fixed")
    if report["stale_workers"]:
        print(f"\n[RESTART NEEDED] {len(report['stale_workers'])} PHP worker(s) still run a "
              "deleted (pre-upgrade) binary. Restart php-fpm / the web server.")
    if report["problems"]:
        print("\n[NOT FULLY CHECKED]")
        for p in report["problems"]:
            print(f"  - {_safe(p)}")
    for limit in report["limits"]:
        print(f"\n[SCOPE] {limit}")
    print("\nVendor data changes fast. Confirm any result against the linked advisory.")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="phpfixed",
                                 description="Is each PHP build on this host fixed for a CVE? "
                                             "Read-only, offline.")
    ap.add_argument("--cve", action="append", help="CVE id to check (repeatable; default: all bundled)")
    ap.add_argument("--json", action="store_true", help="machine-readable output (always every result)")
    ap.add_argument("--all", action="store_true", help="also list fixed results")
    ap.add_argument("--version", action="version", version=f"phpfixed {__version__}")
    args = ap.parse_args(argv)

    try:
        records = load_records()
        known = {r["cve"] for r in records}
        cves = sorted(set(args.cve or known))
        missing = [c for c in cves if c not in known]
        if not cves or missing:
            print(f"phpfixed: no bundled data for {', '.join(missing) or 'any CVE'}", file=sys.stderr)
            return 3
        inv = collect(libs={r["package"]: r["module"] for r in records if r.get("file")},
                      files={r["file"]: r["module"] for r in records if r.get("file")})
        report = resolve(inv, records, cves, strict=bool(args.cve))
    except Exception as e:  # report, don't traceback, on a production host
        print(f"phpfixed: error: {_safe(e)}", file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps({"host": inv["os"], "cves": cves, **report}, indent=2))
    else:
        _table(inv, report, args.all)
    return exit_code(report)
