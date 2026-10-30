"""Readers for the five primary vendor feeds. Each one turns one CVE into
records, or logs why it gives none. Feed content is data: it is parsed with
json and fixed patterns, and never executed or followed as instructions.

eol (php.net end-of-life branches and their final releases) is passed for
PHP only, so it can never pin an OpenSSL branch."""

import functools
import html
import json
import re

from stillmapped.vercmp import branch, compare

from . import origin

DEBIAN = {"12": "bookworm", "13": "trixie"}
DEB_SRC = {"php": {"12": "php8.2", "13": "php8.4"}, "openssl": {"12": "openssl", "13": "openssl"}}
# Owner's answer 6: the binary package that installs libcrypto.so.3, checked by
# hand against each file list on the date given (test_sync checks this table).
DEB_LIBCRYPTO = {
    "12": ("libssl3", "https://packages.debian.org/bookworm/amd64/libssl3/filelist", "2026-10-30"),
    "13": ("libssl3t64", "https://packages.debian.org/trixie/amd64/libssl3t64/filelist", "2026-10-30"),
}
UBUNTU = {"22.04": "Ubuntu:22.04:LTS", "24.04": "Ubuntu:24.04:LTS", "26.04": "Ubuntu:26.04:LTS", "26.10": "Ubuntu:26.10"}
UBU_SRC = {"php": {"22.04": "php8.1", "24.04": "php8.3", "26.04": "php8.5", "26.10": "php8.5"},
           "openssl": dict.fromkeys(UBUNTU, "openssl")}
UBU_LIBCRYPTO = ("libssl3", "libssl3t64")
RHEL_MAIN = {"Red Hat Enterprise Linux AppStream (v. 9)", "Red Hat Enterprise Linux BaseOS (v. 9)"}
RHEL_PKG = {"php": "php", "openssl": "openssl-libs"}
SLES_PKG = {"php": {"php7", "php8"}, "openssl": {"libopenssl3"}}
FILE = {"openssl": "libcrypto.so.3"}
_DEB = functools.cmp_to_key(lambda a, b: compare("vercmp-deb", a, b))
_RH_ID = re.compile(r"^([^:]+):(.+?)-(\d+):([^-:]+)-([^:]+)\.([a-z0-9_]+)(?:::(.+))?$")
_SUSE_ID = re.compile(r"^SUSE Linux Enterprise (.+?) 15 SP(\d+)(-\w+)?:(.+)-([^-]+)-([^-]+)$")


def highest(scheme, versions, pick=max):
    """Owner's rule: several fix versions for one fix give the highest,
    never the lowest. None (skip and log) when they span branches or two
    different strings compare equal. pick=min serves Debian's pre-release case."""
    vs = sorted(set(versions))
    try:
        top = pick(vs, key=functools.cmp_to_key(lambda a, b: compare(scheme, a, b)))
        ties = [v for v in vs if compare(scheme, v, top) == 0]
    except (ValueError, IndexError):
        return None
    return top if len({branch(v) for v in vs}) == 1 and ties == [top] else None


def text(s):
    return html.unescape(re.sub(r"<[^>]+>", " ", s))


def _table(page, after):
    """Rows of the first table after the text 'after', as lists of cell texts."""
    i = page.find(after)
    j = page.find("</table>", i)
    if i < 0 or j < 0:
        return None
    rows = re.findall(r"<tr>(.*?)</tr>", page[i:j], re.S)
    return [c for c in ([" ".join(text(td).split()) for td in re.findall(r"<td>(.*?)</td>", r, re.S)] for r in rows) if c]


def debian(snap, cve, module, out, eol):
    url = f"https://security-tracker.debian.org/tracker/{cve}"
    page = snap.get(url)
    shipped_t = page and _table(page.decode("utf-8", "replace"), "<h2>Vulnerable and fixed packages")
    fixed_t = page and _table(page.decode("utf-8", "replace"), "data on fixed versions")
    if shipped_t is None or fixed_t is None or any(len(r) != 4 for r in shipped_t) or any(len(r) != 7 for r in fixed_t):
        return out.skip(cve, "debian", "*", "*", "tracker page missing or not in the expected format")
    shipped, src = {}, ""
    for r in shipped_t:  # source cell is empty on continuation rows
        src = r[0].split(" (")[0] or src
        for suite in r[1].split(" (")[0].split(", "):
            shipped.setdefault((src, suite), []).append((r[2], r[3]))
    fixed = {(r[0], r[2]): (r[3], r[4], r[5]) for r in fixed_t if r[1] == "source"}
    for stream, suite in DEBIAN.items():
        src = DEB_SRC[module][stream]
        rows = shipped.get((src, suite))
        if not rows:
            continue  # the package is not in this release
        pkg = DEB_LIBCRYPTO[stream][0] if module == "openssl" else src
        rec = {"vendor": "debian", "stream": stream, "package": pkg, "evidence_url": url}
        f, urgency, adv = fixed.get((src, suite)) or fixed.get((src, "(unstable)")) or (None, "", "")
        if f in (None, "(not affected)"):
            out.skip(cve, "debian", stream, pkg, f"no fixed version for {suite}" if f is None else "not affected")
        elif f == "(unfixed)":
            states, branches = {s for _, s in rows}, {branch(v) for v, _ in rows}
            if urgency or states != {"vulnerable"} or len(branches) != 1:
                out.skip(cve, "debian", stream, pkg, f"unfixed, not plainly vulnerable: {urgency or sorted(states)}")
            else:
                out.add(cve, module, {**rec, "branch": branches.pop(), "status": "not-fixed",
                                      "evidence": f"{src} {suite}: vulnerable, no fixed version"})
        elif o := origin.build(origin.debian(stream), f, eol.get(branch(f))):
            out.add(cve, module, {**rec, "branch": branch(f), "status": "fixed", "match": "vercmp-deb", "fixed": f,
                                  "origin": o, "evidence": f"{src} {suite} fixed {f}" + (f", {adv}" if adv else "")})
        elif re.fullmatch(r"(\d+:)?\d+\.\d+\.\d+-\d+", f):
            # Owner's answer 5: fixed before the release shipped, so every build
            # of the release carries the fix. The tracker lists only today's
            # builds; fixed is the LOWEST build ever published in the release's
            # own ~debNuM format, same branch, newer than the fix (owner's option
            # A, 2026-10-30), so a host on an older point release reads fixed.
            vs = sorted((v for v, _ in rows), key=_DEB)
            hist = [v for v in _history(snap, src) or [] if re.fullmatch(rf"(\d+:)?\d+\.\d+\.\d+-\d+~deb{stream}u\d+", v) and branch(v) == branch(f) and compare("vercmp-deb", v, f) > 0]
            o = (low := highest("vercmp-deb", hist, min)) and origin.build(origin.debian(stream)[:1], low, eol.get(branch(low)))
            if {s for _, s in rows} != {"fixed"} or any(compare("vercmp-deb", v, f) <= 0 for v in vs) or not o:
                out.skip(cve, "debian", stream, pkg, f"fixed in {f} before {suite}, but {suite} ships {vs} not all fixed and newer, or snapshot.debian.org lists no clean lowest ~deb{stream}u build: {sorted(hist)}")
            else:
                out.add(cve, module, {**rec, "branch": branch(low), "status": "fixed", "match": "vercmp-deb", "fixed": low, "origin": o,
                                      "evidence": f"{src} fixed in {f} before {suite}; lowest {suite} build on snapshot.debian.org: {low}"})
        else:
            out.skip(cve, "debian", stream, pkg, f"fixed version {f} is not in the {suite} format")


def _history(snap, src):  # every version snapshot.debian.org has of a source package, or None
    page = snap.get(f"https://snapshot.debian.org/mr/package/{src}/")  # offline, a missing page is an error
    try:
        return [r["version"] for r in json.loads(page)["result"]]
    except (TypeError, ValueError, KeyError):
        return None


def ubuntu_index(snap, module):
    """Canonical's OSV records (CVE and USN) per Ubuntu release, one query per
    source package; None for a release whose query failed."""
    index = {}
    for stream, eco in UBUNTU.items():
        vulns, token = [], None
        while vulns is not None:
            q = {"package": {"name": UBU_SRC[module][stream], "ecosystem": eco}, **({"page_token": token} if token else {})}
            data = snap.get("https://api.osv.dev/v1/query", json.dumps(q, sort_keys=True))
            d = json.loads(data) if data else None
            vulns = None if d is None else vulns + d.get("vulns", [])
            token = d and d.get("next_page_token")
            if not token:
                break
        index[stream] = vulns
    return index


def _entries(vuln, eco, name):
    return [a for a in vuln.get("affected", []) if a.get("package", {}).get("ecosystem") == eco and a["package"].get("name") == name]


def _fixed(entry):
    return [e["fixed"] for r in entry.get("ranges", []) for e in r.get("events", []) if "fixed" in e]


def _usn_order(vuln):
    return tuple(int(x) for x in re.findall(r"\d+", vuln["id"]))


def ubuntu(snap, index, cve, module, out):
    for stream, vulns in index.items():
        eco, src = UBUNTU[stream], UBU_SRC[module][stream]
        if vulns is None:
            out.skip(cve, "ubuntu", stream, src, "OSV query failed")
            continue
        recs = [v for v in vulns if v.get("id") == f"UBUNTU-{cve}"]
        if not recs:
            continue  # Canonical lists no record of this CVE for this package and release
        es = [e for v in recs for e in _entries(v, eco, src)]
        fx = _fixed(es[0]) if len(es) == 1 else []
        if len(fx) != 1:
            out.skip(cve, "ubuntu", stream, src, "no single fixed version in Canonical's record (affected with no fix, or several entries)")
            continue
        f, pkg = fx[0], src
        if module == "openssl":
            bins = {b.get("binary_name"): b.get("binary_version") for b in es[0].get("ecosystem_specific", {}).get("binaries", [])}
            names = [n for n in UBU_LIBCRYPTO if n in bins]
            if len(names) != 1 or bins[names[0]] != f:
                out.skip(cve, "ubuntu", stream, src, f"no single libcrypto binary at {f}: {names}")
                continue
            pkg = names[0]
        # The package query does not return every USN, so each USN the CVE
        # record names is read by id.
        related = [json.loads(snap.get(f"https://api.osv.dev/v1/vulns/{u}") or b"{}") for r in recs
                   for u in r.get("related", []) if re.fullmatch(r"USN-\d+-\d+", u)]
        usns = {v["id"]: [x for e in _entries(v, eco, src) for x in _fixed(e)]
                for v in related if {cve, f"UBUNTU-{cve}"} & set(v.get("upstream", [])) and _entries(v, eco, src)}
        # Owner's rule: the highest of the versions the CVE record and its USNs
        # give; the receipt is the first USN that carries exactly that version.
        top = highest("vercmp-deb", [f] + [x for fx in usns.values() for x in fx])
        carry = sorted((u for u, fx in usns.items() if fx == [top]), key=lambda u: _usn_order({"id": u}))
        o = top and origin.ubuntu(top)
        if not carry or not o:
            why = f"{top} is not in Ubuntu's format" if carry else f"no USN carries the highest fix ({top})"
            out.skip(cve, "ubuntu", stream, pkg, f"{why}; CVE record {f}, USNs {usns}" if top else f"fix versions do not compare cleanly: {f}, {usns}")
            continue
        if module == "openssl" and top != f:
            out.skip(cve, "ubuntu", stream, pkg, f"highest fix {top} is newer than the CVE record's {f}, whose binaries named the library")
            continue
        out.add(cve, module, {"vendor": "ubuntu", "stream": stream, "package": pkg, "branch": branch(top), "status": "fixed",
                              "match": "vercmp-deb", "fixed": top, "origin": o,
                              "evidence_url": f"https://ubuntu.com/security/notices/{carry[0]}",
                              "evidence": f"{carry[0]}: {src} {top} ({eco}); CVE record {f}"})


def _vuln(snap, url):
    data = snap.get(url)
    vulns = json.loads(data).get("vulnerabilities", []) if data else []
    return vulns[0] if len(vulns) == 1 else None


def rhel(snap, cve, module, out, eol):
    pkg = RHEL_PKG[module]
    url = f"https://security.access.redhat.com/data/csaf/v2/vex/{cve.split('-')[1]}/{cve.lower()}.json"
    doc = json.loads(snap.get(url) or b"{}")
    v = _vuln(snap, url)
    if v is None:
        return out.skip(cve, "rhel", "9", pkg, "no Red Hat VEX file, or not one vulnerability in it")
    main, stack = set(), list(doc.get("product_tree", {}).get("branches", []))
    while stack:  # product ids of the RHEL 9 main stream, by product name
        n = stack.pop()
        stack += n.get("branches", [])
        if n.get("product", {}).get("name") in RHEL_MAIN:
            main.add(n["product"]["product_id"])
    groups = {}  # module stream (None for a plain package) -> {version: [product ids]}
    for pid in v.get("product_status", {}).get("fixed", []):
        m = _RH_ID.match(pid)
        if m and m[1] in main and m[2] == pkg:
            ver = f"{m[4]}-{m[5]}" if m[3] == "0" else f"{m[3]}:{m[4]}-{m[5]}"  # rpm shows epoch 0 as (none)
            groups.setdefault(m[7], {}).setdefault(ver, []).append(pid)
    if not groups:
        affected = f"red_hat_enterprise_linux_9:{pkg}" in v.get("product_status", {}).get("known_affected", [])
        return out.skip(cve, "rhel", "9", pkg, "affected, no fix (branch not stated)" if affected else "no fixed build in the RHEL 9 main stream")
    for stream_mod, vers in sorted(groups.items(), key=lambda g: str(g[0])):
        ver = highest("vercmp-rpm", vers)  # owner's rule when architectures disagree
        ids = vers.get(ver, [])
        urls = {r.get("url") for r in v.get("remediations", []) if r.get("category") == "vendor_fix" and set(ids) & set(r.get("product_ids", []))}
        o = ver and origin.build(origin.RHEL, ver, eol.get(branch(ver)))
        if not o or len(urls) != 1:
            out.skip(cve, "rhel", "9", pkg, f"{stream_mod or 'plain'}: no clean highest version, not in RHEL format, or not one erratum: {sorted(vers)} {sorted(urls)}")
            continue
        out.add(cve, module, {"vendor": "rhel", "stream": "9", "package": pkg, "branch": branch(ver), "status": "fixed",
                              "match": "vercmp-rpm", "fixed": ver, "origin": o, "evidence_url": urls.pop(),
                              "evidence": f"{pkg}-{ver} ({stream_mod or 'no module'}), RHEL 9 main stream"})


def sles(snap, cve, module, out, eol):
    url = f"https://ftp.suse.com/pub/projects/security/csaf-vex/{cve.split('-')[1]}/{cve.lower()}.json"
    v = _vuln(snap, url)
    cve_page = f"https://www.suse.com/security/cve/{cve}"
    if v is None or cve_page not in [r.get("url") for r in v.get("references", [])]:
        return out.skip(cve, "sles", "*", "*", "no SUSE VEX file, or no CVE page reference in it")
    groups = {}  # (service pack, package) -> {version: [products]}, products with no suffix only
    for pid in v.get("product_status", {}).get("recommended", []):
        m = _SUSE_ID.match(pid)
        if m and not m[3] and m[4] in SLES_PKG[module]:
            groups.setdefault((m[2], m[4]), {}).setdefault(f"{m[5]}-{m[6]}", []).append(m[1])
    if not groups:
        return out.skip(cve, "sles", "*", "*", "no recommended build for a SLES 15 service pack")
    for (sp, pkg), vers in sorted(groups.items()):
        ver = highest("vercmp-rpm", vers)  # owner's rule when products disagree
        o = ver and origin.build(origin.SLES, ver, eol.get(branch(ver)))
        if not o or "Server" not in {p for ps in vers.values() for p in ps}:
            out.skip(cve, "sles", f"15.{sp}", pkg, f"no SLES Server product, no clean highest version, or not in SUSE format: {sorted(vers)}")
            continue
        out.add(cve, module, {"vendor": "sles", "stream": f"15.{sp}", "package": pkg, "branch": branch(ver), "status": "fixed",
                              "match": "vercmp-rpm", "fixed": ver, "origin": o, "evidence_url": cve_page,
                              "evidence": f"SUSE Linux Enterprise Server 15 SP{sp}: recommended {pkg}-{ver}"})


def phpnet(snap, year):
    """php.net data: ChangeLog sections, security releases, news items, and
    the final release of each end-of-life branch."""
    get = lambda u: (snap.get(u) or b"").decode("utf-8", "replace")
    sections = [(v, text(body)) for v, body in re.findall(r'<section class="version" id="(\d+\.\d+\.\d+)">(.*?)</section>',
                                                          get("https://www.php.net/ChangeLog-8.php"), re.S)]
    releases = json.loads(get("https://www.php.net/releases/index.php?json&max=1000&version=8") or "{}")
    eol = {}
    for row in re.findall(r"<tr>(.*?)</tr>", get("https://www.php.net/eol.php"), re.S):
        if m := re.search(r"<td>\s*(\d+\.\d+)\s*</td>.*?/releases#(\1\.\d+)\"", row, re.S):
            eol[m[1]] = m[2]
    news = []
    for y in range(year - 3, year + 1):
        for item in re.findall(r'<article class="newsItem">(.*?)</article>', get(f"https://www.php.net/archive/{y}.php"), re.S):
            if m := re.search(r'<a id="(\d{4}-\d\d-\d\d-\d+)" href="(https://www\.php\.net/archive/\d{4}\.php#\1)"', item):
                news.append((tuple(int(x) for x in m[1].split("-")), m[2], " ".join(text(item).split())))
    return {"sections": sections, "releases": releases, "eol": eol, "news": sorted(news)}


def upstream(php, cve, out):
    keys = {cve} | {g for _, _, t in php["news"] for c, g in re.findall(r"(CVE-\d{4}-\d+) \( ?(GHSA-[0-9a-z-]+) ?\)", t) if c == cve}
    hit = lambda t: any(re.search(rf"(?<![\w-]){re.escape(k)}(?![\w-])", t) for k in keys)
    by_branch = {}
    for v, t in php["sections"]:
        if hit(t):
            by_branch.setdefault(branch(v), []).append(v)
    fixes = [highest("upstream", vs) for vs in by_branch.values()]
    names = lambda t, v: re.search(rf"(?<![\d.]){re.escape(v)}(?![\d.])", t)
    for br, vs in sorted(by_branch.items()):
        v = highest("upstream", vs)  # owner's rule: a later re-fix wins
        # The receipt must name this fixed release: the item naming the CVE and
        # v that names the most of the CVE's fixed releases (the advisory
        # covering the whole fix), earliest on a tie; else the "PHP v Released" item.
        named = [(-sum(bool(names(t, f)) for f in fixes if f), k, u) for k, u, t in php["news"] if v and hit(t) and names(t, v)]
        url = min(named)[2] if named else next((u for _, u, t in php["news"] if v and re.search(rf"PHP {re.escape(v)} Released", t)), None)
        if not v or "security" not in php["releases"].get(v, {}).get("tags", []) or not url:
            out.skip(cve, "upstream", "*", "php", f"{br}: ChangeLog lists {vs}; no clean highest release tagged security with a news item")
            continue
        out.add(cve, "php", {"vendor": "upstream", "stream": "*", "package": "php", "branch": br, "status": "fixed",
                             "match": "upstream", "fixed": v, "evidence_url": url,
                             "evidence": f"php.net ChangeLog {v} lists {', '.join(sorted(keys))}; release tagged security"})
