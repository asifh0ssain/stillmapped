"""Data generator for phpfixed. Runs on a maintainer's machine, never on a scanned host.

  python3 -m tools.sync fetch            network: new snapshot under tools/sync/snapshots/
  python3 -m tools.sync build SNAPSHOT   offline: records to tools/sync/out/, plus skipped.tsv
  python3 -m tools.sync oracle           compare tools/sync/out/ with phpfixed/data/php2shell.json
"""

import datetime
import os
import sys

from .build import oracle, run, write
from .snap import Snapshot

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")


def main(argv):
    cmd, rest = (argv[0], argv[1:]) if argv else ("", [])
    if cmd == "fetch" and not rest:
        path = os.path.join(HERE, "snapshots", datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
        snap = Snapshot(path, online=True)
        try:
            run(snap)
        finally:
            snap.save()
        print(path)
    elif cmd == "build" and len(rest) == 1:
        write(run(Snapshot(rest[0])), OUT)
        print(OUT)
    elif cmd == "oracle" and not rest:
        diffs, extras = oracle(OUT, os.path.join(HERE, "..", "..", "phpfixed", "data", "php2shell.json"))
        for line in [f"extra: {e}" for e in extras] + [f"DIFF: {d}" for d in diffs]:
            print(line)
        print(f"oracle: {len(diffs)} difference(s)" if diffs else "oracle: all hand records reproduced")
        return 1 if diffs else 0
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


sys.exit(main(sys.argv[1:]))
