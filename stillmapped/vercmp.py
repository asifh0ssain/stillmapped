"""Version ordering for Debian (dpkg) and RPM package versions, and plain
upstream PHP releases. All comparators return -1, 0 or 1.

The Debian and RPM orderings follow dpkg's verrevcmp() and rpm's
rpmvercmp(). Character classes are ASCII-only, as in the C originals.
"""

import itertools
import re


def _cmp(a, b):
    return (a > b) - (a < b)


def split_evr(evr):
    """'[epoch:]version[-release]' -> (epoch, version, release)."""
    epoch, sep, rest = evr.strip().partition(":")
    if not sep:
        epoch, rest = "0", epoch
    if not (epoch.isascii() and epoch.isdigit()):
        raise ValueError(f"bad epoch: {epoch!r}")
    version, _, release = rest.rpartition("-") if "-" in rest else (rest, "", "")
    if not version:
        raise ValueError(f"empty version in {evr!r}")
    return int(epoch), version, release


# --- Debian ---------------------------------------------------------------

def _deb_runs(s):
    # Alternating non-digit and digit runs. In a non-digit run '~' sorts
    # before the end of the string (0), letters before other characters.
    def order(c):
        return -1 if c == "~" else ord(c) if c.isascii() and c.isalpha() else ord(c) + 256
    return [([order(c) for c in text] + [0], int(digits or 0))
            for text, digits in re.findall(r"([^0-9]*)([0-9]*)", s)]


def _verrevcmp(a, b):
    # A string that has ended compares as an empty run and the number 0.
    for x, y in itertools.zip_longest(_deb_runs(a), _deb_runs(b), fillvalue=([0], 0)):
        if x != y:
            return _cmp(x, y)
    return 0


def compare_deb(a, b):
    (ea, ua, ra), (eb, ub, rb) = split_evr(a), split_evr(b)
    return _cmp(ea, eb) or _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


# --- RPM ------------------------------------------------------------------

_RPM_TOKEN = re.compile(r"[0-9]+|[a-zA-Z]+|~|\^")


def _rank(token):
    # '~' sorts before everything, even the end (None); '^' after the end
    # but before any alphanumeric segment.
    return {"~": 0, None: 1, "^": 2}.get(token, 3)


def rpmvercmp(a, b):
    """Compare one version or release field, as rpm's rpmvercmp()."""
    for x, y in itertools.zip_longest(_RPM_TOKEN.findall(a), _RPM_TOKEN.findall(b)):
        if _rank(x) != _rank(y):
            return _cmp(_rank(x), _rank(y))
        if _rank(x) < 3:
            continue
        if x.isdigit() != y.isdigit():
            return 1 if x.isdigit() else -1  # numeric is newer than alpha
        if x.isdigit():
            x, y = int(x), int(y)
        if x != y:
            return _cmp(x, y)
    return 0


def compare_rpm(a, b):
    (ea, va, ra), (eb, vb, rb) = split_evr(a), split_evr(b)
    return _cmp(ea, eb) or rpmvercmp(va, vb) or rpmvercmp(ra, rb)


# --- Upstream PHP ---------------------------------------------------------

def branch(version):
    """PHP branch ('8.2') from any version string, ignoring an epoch."""
    m = re.match(r"(?:\d+:)?(\d+)\.(\d+)", version)
    return f"{m.group(1)}.{m.group(2)}" if m else ""


def _release(version):
    # Only a plain release is comparable. 8.5.12RC1 and 8.5.12-dev are not
    # 8.5.12, and guessing their order could call a pre-release fixed.
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version.strip())
    if not m:
        raise ValueError(f"not a plain PHP release: {version!r}")
    return tuple(int(g) for g in m.groups())


def compare_upstream(a, b):
    """Compare plain PHP releases like '8.5.12' (Docker, Homebrew, DirectAdmin)."""
    return _cmp(_release(a), _release(b))


SCHEMES = {
    "vercmp-deb": compare_deb,
    "vercmp-rpm": compare_rpm,
    "upstream": compare_upstream,
}


def compare(scheme, a, b):
    try:
        fn = SCHEMES[scheme]
    except KeyError:
        raise ValueError(f"unknown version scheme: {scheme!r}") from None
    return fn(a, b)
