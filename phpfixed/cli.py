"""phpfixed command line. Read-only and offline."""

import argparse
import json
import sys

from . import __version__
from .collect import collect
from .resolve import exit_code, load_records, resolve


def _table(inv, report):
    print(f"phpfixed {__version__}  host: {inv['os']['id']} {inv['os']['stream']}")
    if not report["results"]:
        print("\nNo PHP builds found.")
    for r in report["results"]:
        b = r["build"]
        print(f"\n[{r['status'].upper()}] {r['cve']}  {b['vendor']}/{b['package']} {b['version']}")
        print(f"  from:   {b['source']} ({b['where']})")
        print(f"  why:    {r['reason']}")
        if r["record"]:
            print(f"  source: {r['record']['evidence_url']} (checked {r['record']['checked']})")
    if report["stale_workers"]:
        print(f"\n[RESTART NEEDED] {len(report['stale_workers'])} PHP worker(s) still run a "
              "deleted (pre-upgrade) binary. Restart php-fpm / the web server.")
    if inv["workers_unreadable"]:
        print(f"\nnote: {inv['workers_unreadable']} process(es) unreadable; run as root "
              "to check every running worker.")
    print("\nVendor data changes fast. Confirm any result against the linked advisory.")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="phpfixed",
                                 description="Is each PHP build on this host fixed for a CVE? "
                                             "Read-only, offline.")
    ap.add_argument("--cve", action="append", help="CVE id to check (repeatable; default: all bundled)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--version", action="version", version=f"phpfixed {__version__}")
    args = ap.parse_args(argv)

    try:
        records = load_records(set(args.cve) if args.cve else None)
        cves = sorted(set(args.cve) if args.cve else {r["cve"] for r in records})
        if not cves:
            print("phpfixed: no CVE data bundled", file=sys.stderr)
            return 3
        inv = collect()
        report = resolve(inv, records, cves)
    except Exception as e:  # report, don't traceback, on a production host
        print(f"phpfixed: error: {e}", file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps({"host": inv["os"], "cves": cves, **report,
                          "workers_unreadable": inv["workers_unreadable"]}, indent=2))
    else:
        _table(inv, report)
    return exit_code(report)


if __name__ == "__main__":
    sys.exit(main())
