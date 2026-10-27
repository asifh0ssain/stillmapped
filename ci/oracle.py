"""CI: diff phpfixed's version ordering against the real dpkg or rpm.

Usage: python3 -m ci.oracle deb|rpm N   (from the repo root)
Generates N random version pairs and fails on any pair the real tool orders
differently. deb compares full epoch:upstream-revision strings with
'dpkg --compare-versions'; rpm compares version fields with rpm's own
rpmvercmp through its Lua interpreter.
"""

import os
import random
import subprocess
import sys
import tempfile

from phpfixed.vercmp import compare_deb, rpmvercmp


def gen(rng, chars, n):
    return rng.choice("0123456789") + "".join(rng.choice(chars) for _ in range(rng.randint(0, n)))


def deb_version(rng):
    v = gen(rng, "0123456789abAB.+~", 8)
    if rng.random() < 0.3:
        v = f"{rng.randint(0, 2)}:{v}"
    if rng.random() < 0.6:
        v += "-" + gen(rng, "0123456789ab.+~", 5)
    return v


def dpkg_cmp(a, b):
    for op, result in (("lt", -1), ("gt", 1)):
        if subprocess.run(["dpkg", "--compare-versions", a, op, b]).returncode == 0:
            return result
    return 0


def rpm_cmps(pairs):
    with tempfile.NamedTemporaryFile("w", suffix=".lua", delete=False) as f:
        for a, b in pairs:
            f.write(f"print(rpm.vercmp({a!r}, {b!r}))\n")
    try:
        out = subprocess.run(["rpm", "--eval", f"%{{lua: dofile('{f.name}')}}"],
                             capture_output=True, text=True, check=True).stdout
    finally:
        os.unlink(f.name)
    return [max(-1, min(1, int(x))) for x in out.split()]


def main(kind, n):
    rng = random.Random(int(os.environ.get("SEED", "1")))
    if kind == "deb":
        pairs = [(deb_version(rng), deb_version(rng)) for _ in range(n)]
        ours, real = [compare_deb(a, b) for a, b in pairs], [dpkg_cmp(a, b) for a, b in pairs]
    else:
        pairs = [(gen(rng, "0123456789abAB.~^_+", 8), gen(rng, "0123456789abAB.~^_+", 8))
                 for _ in range(n)]
        ours, real = [rpmvercmp(a, b) for a, b in pairs], rpm_cmps(pairs)
    bad = [(p, o, r) for p, o, r in zip(pairs, ours, real) if o != r]
    for (a, b), o, r in bad[:20]:
        print(f"MISMATCH {a!r} vs {b!r}: phpfixed {o}, {kind} {r}")
    print(f"{kind}: {n - len(bad)}/{n} pairs agree")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], int(sys.argv[2])))
