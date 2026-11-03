# Vendor version grammars and the anchored origin patterns built from them.
#
# A template is the origin pattern with placeholders. The same template parses
# the vendor's fixed version (placeholders become capture groups) and builds the
# origin (placeholders become the parsed literals), so a fixed version that does
# not fit the vendor's grammar gives no origin, and so no record.
#   <E> epoch with its colon, kept literal (or absent)
#   <M> <m> major and minor, kept literal
#   <P> upstream patch level: \d+, or literal when pinned (see pin)
#   <S> SUSE codestream marker such as 150700, kept literal
# Every template is anchored with ^ and $ and has no |.

import re

_GROUPS = {"E": r"(\d+:)?", "M": r"(\d+)", "m": r"(\d+)", "P": r"(\d+)", "S": r"(1\d0\d00)"}


def debian(stream, release=False):
    # Debian uses both markers in one release: ~debNuM for point updates,
    # +debNuM for security (CI run #3, owner 2026-11-02). release: the release's
    # own plain build too (fixed before the release, not affected; owner 2026-11-03).
    return [rf"^<E><M>\.<m>\.<P>-\d+{'(' * release}[~+]deb{stream}u\d+{')?' * release}$"]


# The second module template is for builds whose minor carries Red Hat's
# literal ".z" (owner's approval 2026-10-30); it is tried only when the first
# fails, so it never changes an origin built from a plain module version.
RHEL = [r"^<E><M>\.<m>\.<P>-\d+\.module\+el9\.\d+\.\d+\+\d+\+[0-9a-f]{8}$",
        r"^<E><M>\.<m>\.<P>-\d+\.module\+el9\.\d+\.\d+(\.z)?\+\d+\+[0-9a-f]{8}$"]
# Red Hat compares one NEVRA line per package, across rebases (owner 2026-11-03):
# a plain (non-module) package gets one record per release, any upstream version.
RHEL_ANY = r"^<E>\d+\.\d+\.\d+-\d+\.el9(_\d+)?(\.\d+)*$"
SLES = [r"^<E><M>\.<m>\.<P>-<S>\.\d+(\.\d+)*$"]
# Ubuntu does not change upstream within a release; only the last counter moves.
_UBUNTU = re.compile(r"^((?:\d+:)?\d[0-9a-z.+~]*-[0-9a-z.]*ubuntu[0-9a-z.]*\.)\d+$")


def esc(s):
    """Escape . and + only, as the hand records do (re.escape would also
    escape - and ~). The grammars admit no other regex character."""
    return s.replace(".", r"\.").replace("+", r"\+")


def build(templates, version, final=None):
    """Origin for version under the first template it fits, or None.
    final: php.net's last release of the branch when the branch is end of
    life; a fix in exactly that release pins the patch level, since no later
    upstream import can exist."""
    for t in templates:
        names = re.findall(r"<(\w)>", t)
        m = re.match(re.sub(r"<(\w)>", lambda g: _GROUPS[g[1]], t), version)
        if not m:
            continue
        v = dict(zip(names, m.groups()))  # placeholders come before any other group
        pin = final is not None and "P" in v and final == f"{v['M']}.{v['m']}.{v['P']}"
        lit = {**v, "E": v["E"] or "", "P": v["P"] if pin else r"\d+"}
        return re.sub(r"<(\w)>", lambda g: lit[g[1]], t)
    return None


def fill(template, br):  # origin for every build of branch br, when the vendor names no version
    return re.sub(r"<(\w)>", lambda g: {"E": "", "M": br.split(".")[0], "m": br.split(".")[1], "P": r"\d+"}[g[1]], template)


def ubuntu(version):
    m = _UBUNTU.match(version)
    return m and f"^{esc(m[1])}\\d+$"
