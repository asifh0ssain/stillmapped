"""Version ordering for Debian (dpkg) and RPM package versions.

Pure-Python ports of dpkg's verrevcmp() and rpm's rpmvercmp(). All
comparators return -1, 0 or 1. Character classes are ASCII-only, matching
the C originals.
"""

import re

_DIGITS = "0123456789"
_ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _sign(n):
    return (n > 0) - (n < 0)


def _isdigit(c):
    return c != "" and c in _DIGITS


def _isalpha(c):
    return c != "" and c in _ALPHA


def _at(s, i):
    return s[i] if i < len(s) else ""


# --- Debian ---------------------------------------------------------------

def _deb_order(c):
    # dpkg lib/dpkg/version.c order(): '~' sorts before end of string,
    # letters before non-letters.
    if c == "" or _isdigit(c):
        return 0
    if _isalpha(c):
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _verrevcmp(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (_at(a, i) and not _isdigit(a[i])) or (_at(b, j) and not _isdigit(b[j])):
            ac, bc = _deb_order(_at(a, i)), _deb_order(_at(b, j))
            if ac != bc:
                return _sign(ac - bc)
            i += 1
            j += 1
        while _at(a, i) == "0":
            i += 1
        while _at(b, j) == "0":
            j += 1
        while _isdigit(_at(a, i)) and _isdigit(_at(b, j)):
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if _isdigit(_at(a, i)):
            return 1
        if _isdigit(_at(b, j)):
            return -1
        if first_diff:
            return _sign(first_diff)
    return 0


def split_deb(version):
    """'[epoch:]upstream[-revision]' -> (epoch, upstream, revision)."""
    version = version.strip()
    epoch = 0
    if ":" in version:
        e, version = version.split(":", 1)
        if not e.isdigit():
            raise ValueError(f"bad epoch in Debian version: {e!r}")
        epoch = int(e)
    if "-" in version:
        upstream, revision = version.rsplit("-", 1)
    else:
        upstream, revision = version, ""
    if not upstream:
        raise ValueError("empty upstream version")
    return epoch, upstream, revision


def compare_deb(a, b):
    ea, ua, ra = split_deb(a)
    eb, ub, rb = split_deb(b)
    if ea != eb:
        return _sign(ea - eb)
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


# --- RPM ------------------------------------------------------------------

def _isalnum(c):
    return _isdigit(c) or _isalpha(c)


def rpmvercmp(a, b):
    """Compare one version or release field, as rpm's rpmvercmp()."""
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        while _at(a, i) and not _isalnum(a[i]) and a[i] not in "~^":
            i += 1
        while _at(b, j) and not _isalnum(b[j]) and b[j] not in "~^":
            j += 1
        ca, cb = _at(a, i), _at(b, j)

        # '~' sorts before everything, including end of string.
        if ca == "~" or cb == "~":
            if ca != "~":
                return 1
            if cb != "~":
                return -1
            i += 1
            j += 1
            continue

        # '^' sorts after end of string but before anything else.
        if ca == "^" or cb == "^":
            if not ca:
                return -1
            if not cb:
                return 1
            if ca != "^":
                return 1
            if cb != "^":
                return -1
            i += 1
            j += 1
            continue

        if not (ca and cb):
            break

        si, sj = i, j
        isnum = _isdigit(ca)
        same_class = _isdigit if isnum else _isalpha
        while same_class(_at(a, i)):
            i += 1
        while same_class(_at(b, j)):
            j += 1
        sa, sb = a[si:i], b[sj:j]

        # Segments of different classes: numeric is newer than alpha.
        if not sb:
            return 1 if isnum else -1

        if isnum:
            sa, sb = sa.lstrip("0"), sb.lstrip("0")
            if len(sa) != len(sb):
                return 1 if len(sa) > len(sb) else -1
        if sa != sb:
            return 1 if sa > sb else -1

    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


def split_rpm(evr):
    """'[epoch:]version[-release]' -> (epoch, version, release)."""
    evr = evr.strip()
    epoch = 0
    if ":" in evr:
        e, evr = evr.split(":", 1)
        if e:
            if not e.isdigit():
                raise ValueError(f"bad epoch in RPM version: {e!r}")
            epoch = int(e)
    if "-" in evr:
        version, release = evr.rsplit("-", 1)
    else:
        version, release = evr, ""
    if not version:
        raise ValueError("empty RPM version")
    return epoch, version, release


def compare_rpm(a, b):
    ea, va, ra = split_rpm(a)
    eb, vb, rb = split_rpm(b)
    if ea != eb:
        return _sign(ea - eb)
    return rpmvercmp(va, vb) or rpmvercmp(ra, rb)


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
    ra, rb = _release(a), _release(b)
    return (ra > rb) - (ra < rb)


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
