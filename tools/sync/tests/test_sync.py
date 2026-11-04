import glob
import json
import os
import pathlib
import re
import tempfile
import unittest
from unittest.mock import patch

from stillmapped.vercmp import compare

from tools.sync import build, feeds, origin
from tools.sync.snap import Snapshot

DEB12, DEB13 = origin.debian("12"), origin.debian("13")

# Design note section 4: (templates, vendor fixed version, EOL final or None,
# expected origin, the vendor's next update, versions that must fail).
TABLE = [
    (DEB12, "8.2.35-1~deb12u1", None, r"^8\.2\.\d+-\d+[~+]deb12u\d+$", "8.2.36-1+deb12u1",
     ["8.2.35-1~deb12u1+thirdparty1", "1:8.2.35-1~deb12u1", "8.2.35-1~deb12u1+b1", "8.2.35-1-deb12u1",
      "8.2.99-1+0~20261022.1+debian12~1.gbp", "8.3.1-1~deb12u1"]),
    (DEB13, "8.4.27-1~deb13u1", None, r"^8\.4\.\d+-\d+[~+]deb13u\d+$", "8.4.28-1~deb13u1", ["8.4.27-1~deb12u1"]),
    (DEB12, "3.0.14-1~deb12u2", None, r"^3\.0\.\d+-\d+[~+]deb12u\d+$", "3.0.22-1~deb12u2",
     ["3.0.14-1+thirdparty1", "1:3.0.14-1~deb12u2", "3.0.14-1~deb13u1"]),
    (origin.RHEL, "8.2.35-1.module+el9.8.0+25111+a1450321", None,
     r"^8\.2\.\d+-\d+\.module\+el9\.\d+\.\d+\+\d+\+[0-9a-f]{8}$", "8.2.36-1.module+el9.8.0+25200+b2c3d4e5",
     ["8.2.35-1.module+el9.8.0+25111+a1450321.thirdparty1", "1:8.2.35-1.module+el9.8.0+25111+a1450321",
      "8.2.35-1.el9.remi", "8.2.35-1.module+el8.10.0+25110+f67151d2", "8.2.35-1.module_el9.8.0+25111+a1450321"]),
    # Owner's approval 2026-10-30: ".z" is a literal, optional part of the module grammar.
    (origin.RHEL, "8.1.27-1.module+el9.3.0.z+21063+f4ccb976", None,
     r"^8\.1\.\d+-\d+\.module\+el9\.\d+\.\d+(\.z)?\+\d+\+[0-9a-f]{8}$", "8.1.28-1.module+el9.4.0+22000+0a1b2c3d",
     ["8.1.27-1.module+el9.3.0.zz+21063+f4ccb976", "8.1.27-1.module+el9.3.0.Z+21063+f4ccb976",
      "8.1.27-1.module+el9.3.0.z.1+21063+f4ccb976", "8.1.27-1.module+el9.3.0.z+21063+f4ccb976.thirdparty1",
      "1:8.1.27-1.module+el9.3.0.z+21063+f4ccb976", "8.1.27-1.module+el9.3.0z+21063+f4ccb976",
      "8.1.27-1.module+el8.10.0.z+21063+f4ccb976"]),
    # Owner, 2026-11-03: a plain RHEL package, any upstream version (rebases); epoch and el9 literal.
    ([origin.RHEL_ANY], "1:3.0.7-28.el9_4", None, r"^1:\d+\.\d+\.\d+-\d+\.el9(_\d+)?(\.\d+)*$", "1:3.5.8-2.el9_8",
     ["2:3.0.7-28.el9_4", "3.0.7-28.el9_4", "1:3.0.7-28.el9_4.alma", "1:3.0.7-28.el9_4+custom1", "1:3.5.8-2.el8_10",
      "1:3.5.8-2.module+el9.8.0+25111+a1450321"]),
    (origin.SLES, "8.3.36-150700.3.24.1", None, r"^8\.3\.\d+-150700\.\d+(\.\d+)*$", "8.3.37-150700.3.27.1",
     ["8.3.36-150700.3.24.1.thirdparty", "1:8.3.36-150700.3.24.1", "8.3.36-lp156.12.1", "8.3.36-150600.3.24.1"]),
    (origin.SLES, "7.4.33-150400.4.81.1", "7.4.33", r"^7\.4\.33-150400\.\d+(\.\d+)*$", "7.4.33-150400.4.84.1",
     ["7.4.34-150400.4.81.1", "1:7.4.33-150400.4.81.1"]),
]
UBUNTU = [
    ("8.3.6-0ubuntu0.24.04.13", r"^8\.3\.6-0ubuntu0\.24\.04\.\d+$", "8.3.6-0ubuntu0.24.04.14",
     ["8.3.6-0ubuntu0.24.04.13+thirdparty1", "1:8.3.6-0ubuntu0.24.04.14", "8.3.6-0ubuntu0.24.04.13~ppa1",
      "8.3.14-1+ubuntu24.04.1+deb.sury.org+1", "8.3.6-0ubuntu0.22.04.13"]),
    ("3.0.2-0ubuntu1.18", r"^3\.0\.2-0ubuntu1\.\d+$", "3.0.2-0ubuntu1.19",
     ["3.0.2-0ubuntu1.18+Fips1", "1:3.0.2-0ubuntu1.19", "3.0.2-0ubuntu1.18+esm1"]),
    ("8.5.9-0ubuntu2.1", r"^8\.5\.9-0ubuntu2\.\d+$", "8.5.9-0ubuntu2.2", []),
    ("8.1.2-1ubuntu2.28", r"^8\.1\.2-1ubuntu2\.\d+$", "8.1.2-1ubuntu2.29", []),
]


class TestOrigins(unittest.TestCase):
    def test_design_table_rebuilds_and_epochs_fail(self):
        for templates, fixed, final, want, nxt, bad in TABLE:
            o = origin.build(templates, fixed, final)
            self.assertEqual(o, want, fixed)
            self.assertTrue(re.fullmatch(r"\^[^|]*\$", o))
            self.assertTrue(re.search(o, fixed) and re.search(o, nxt), fixed)
            self.assertEqual([b for b in bad if re.search(o, b)], [], fixed)

    def test_ubuntu_rebuilds_pro_and_epochs_fail(self):
        for fixed, want, nxt, bad in UBUNTU:
            o = origin.ubuntu(fixed)
            self.assertEqual(o, want)
            self.assertTrue(re.search(o, nxt))
            self.assertEqual([b for b in bad if re.search(o, b)], [], fixed)

    def test_debian_marker_accepts_both_tilde_and_plus_builds(self):
        # CI run #3: a fix in 3.5.1-1+deb13u1 rejected trixie's own 3.5.7-1~deb13u3.
        for fixed in ("3.5.1-1+deb13u1", "3.5.4-1~deb13u1"):
            o = origin.build(DEB13, fixed)
            self.assertEqual(o, r"^3\.5\.\d+-\d+[~+]deb13u\d+$")
            for good in ("3.5.7-1~deb13u3", "3.5.1-1+deb13u1", "3.5.8-1+deb13u4"):
                self.assertTrue(re.search(o, good), (fixed, good))
            for bad in ("3.5.7-1~deb13u3+thirdparty1", "3.5.1-1+deb13u1+thirdparty1", "1:3.5.7-1~deb13u3",
                        "1:3.5.1-1+deb13u1", "3.5.7-1~deb12u3", "3.5.7-1~~deb13u3"):
                self.assertFalse(re.search(o, bad), (fixed, bad))

    def test_outside_the_grammar_gives_no_origin(self):
        self.assertIsNone(origin.build(DEB12, "8.2.35-1~deb13u1"))
        self.assertIsNone(origin.build(DEB12, "3.3.2-1"))  # fixed before the release: answer 5 path
        self.assertIsNone(origin.build(origin.SLES, "8.3.36-lp156.12.1"))
        self.assertIsNone(origin.ubuntu("3.0.2-0ubuntu1.18+esm1"))
        self.assertIsNone(origin.ubuntu("8.3.14-1+ubuntu24.04.1+deb.sury.org+1"))

    def test_pin_only_on_the_final_release(self):
        self.assertEqual(origin.build(origin.SLES, "7.4.32-150400.4.1", "7.4.33"), r"^7\.4\.\d+-150400\.\d+(\.\d+)*$")


class TestPackageTable(unittest.TestCase):
    def test_debian_libcrypto_owners(self):
        # Owner's answer 6: one row per Debian stream, each with an evidence URL and check date.
        self.assertEqual(set(feeds.DEB_LIBCRYPTO), set(feeds.DEBIAN))
        for stream, (pkg, url, checked) in feeds.DEB_LIBCRYPTO.items():
            self.assertTrue(url.startswith("https://packages.debian.org/") and f"/{pkg}/" in url)
            self.assertRegex(checked, r"^\d{4}-\d\d-\d\d$")
        self.assertEqual({p for p, _, _ in feeds.DEB_LIBCRYPTO.values()}, {"libssl3", "libssl3t64"})


class TestOut(unittest.TestCase):
    def rec(self, **kw):
        return {"vendor": "debian", "stream": "12", "package": "php8.2", "branch": "8.2", "status": "fixed",
                "match": "vercmp-deb", "fixed": "8.2.35-1~deb12u1", "origin": r"^8\.2\.\d+-\d+~deb12u\d+$",
                "evidence_url": "https://security-tracker.debian.org/tracker/CVE-2026-0001", **kw}

    def test_invalid_record_is_skipped_not_written(self):
        out = build.Out("2026-10-30")
        out.add("CVE-2026-0001", "php", self.rec(origin="^8.2"))
        self.assertEqual(out.records, {})
        self.assertTrue(any("validator" in s[4] for s in out.skips))

    def test_several_fixes_for_one_build_keep_the_highest(self):
        # Owner's rule 2026-10-30: the highest, never the lowest.
        out = build.Out("2026-10-30")
        for f in ("8.2.36-1~deb12u1", "8.2.37-1~deb12u1", "8.2.35-1~deb12u1"):
            out.add("CVE-2026-0001", "php", self.rec(fixed=f))
        self.assertEqual([r["fixed"] for r in out.records[("CVE-2026-0001", "php")].values()], ["8.2.37-1~deb12u1"])

    def test_fixed_and_not_fixed_for_one_build_give_no_record(self):
        out = build.Out("2026-10-30")
        out.add("CVE-2026-0001", "php", self.rec())
        nf = {k: v for k, v in self.rec(status="not-fixed").items() if k not in ("match", "fixed", "origin")}
        out.add("CVE-2026-0001", "php", nf)
        out.add("CVE-2026-0001", "php", self.rec(fixed="8.2.40-1~deb12u1"))
        self.assertEqual(out.records[("CVE-2026-0001", "php")], {})


    def test_library_records_carry_the_file(self):
        out = build.Out("2026-10-30")
        out.add("CVE-2026-0002", "openssl", self.rec(package="libssl3", branch="3.0", fixed="3.0.14-1~deb12u2",
                                                    origin=r"^3\.0\.\d+-\d+~deb12u\d+$"))
        (r,) = out.records[("CVE-2026-0002", "openssl")].values()
        self.assertEqual((r["file"], r["checked"]), ("libcrypto.so.3", "2026-10-30"))


class TestHighest(unittest.TestCase):
    def test_highest_never_lowest(self):
        self.assertEqual(feeds.highest("upstream", ["8.3.6", "8.3.12", "8.3.8"]), "8.3.12")
        self.assertEqual(feeds.highest("vercmp-deb", ["8.1.2-1ubuntu2.16", "8.1.2-1ubuntu2.17"]), "8.1.2-1ubuntu2.17")

    def test_unclean_versions_give_none(self):
        self.assertIsNone(feeds.highest("upstream", ["8.3.12", "8.4.1"]))  # two branches
        self.assertIsNone(feeds.highest("vercmp-rpm", ["0:8.2.35-1.el9", "8.2.35-1.el9"]))  # equal, different strings
        self.assertIsNone(feeds.highest("upstream", ["8.3.12", "8.3.13RC1"]))  # does not parse
        self.assertIsNone(feeds.highest("upstream", []))

def sources(*paras):  # a release-day main Sources.xz
    import lzma
    return lzma.compress("\n\n".join(f"Package: {p}\nVersion: {v}\n" + extra for p, v, extra in paras).encode())


class TestDebianBeforeRelease(unittest.TestCase):
    # Owner, 2026-11-03: fixed before the release = the release's own first build.
    CVE, URL = "CVE-2025-27587", "https://security-tracker.debian.org/tracker/CVE-2025-27587"
    SRC = "https://snapshot.debian.org/archive/debian/20250810T000000Z/dists/trixie/main/source/Sources.xz"
    ROW = "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"
    FIXED = "<tr><td>openssl</td><td>source</td><td>{}</td><td>{}</td><td>{}</td><td></td><td></td></tr>"

    def page(self, bookworm="vulnerable", trixie="fixed", unstable="3.5.0-1", urgency="unimportant"):
        return ("<h2>Vulnerable and fixed packages</h2><table>" + self.ROW.format("openssl", "bookworm", "3.0.20-1~deb12u2", bookworm)
                + self.ROW.format("", "bookworm (security)", "3.0.22-1~deb12u2", bookworm)
                + self.ROW.format("", "trixie", "3.5.7-1~deb13u2", trixie) + self.ROW.format("", "trixie (security)", "3.5.7-1~deb13u3", trixie)
                + "</table>data on fixed versions<table>" + self.FIXED.format("(unstable)", unstable, urgency) + "</table>").encode()

    def run_one(self, src=None, **kw):
        pages = {self.URL: self.page(**kw), **({self.SRC: src} if src is not None else {})}
        out = build.Out("2026-11-03")
        feeds.debian(FakeSnap(pages), self.CVE, "openssl", out, {})
        return out.records.get((self.CVE, "openssl"), {}), out.skips

    def test_trixie_release_build_3_5_1_1_reads_fixed_for_cve_2025_27587(self):
        # Part 1 B1, real case: Debian fixed it in 3.5.0-1 before trixie, which released with 3.5.1-1.
        from stillmapped.resolve import resolve_one
        recs, _ = self.run_one(sources(("openssl", "3.5.0-1", "Extra-Source-Only: yes\n"), ("openssl", "3.5.1-1", ""), ("php8.4", "8.4.11-1", "")))
        r = next(r for r in recs.values() if r["stream"] == "13")
        self.assertEqual((r["fixed"], r["origin"]), ("3.5.1-1", r"^3\.5\.\d+-\d+([~+]deb13u\d+)?$"))
        host = {"source": "dpkg", "vendor": "debian", "stream": "13", "package": "libssl3t64", "branch": "3.5",
                "scheme": "vercmp-deb", "where": "libssl3t64", "module": "openssl", "db": "host"}
        rec = {**r, "cve": self.CVE, "module": "openssl"}
        for version, want in (("3.5.1-1", "fixed"), ("3.5.7-1~deb13u3", "fixed"), ("3.5.0-1", "not-fixed"),
                              ("3.5.1-1+thirdparty1", "unknown"), ("1:3.5.1-1", "unknown")):
            self.assertEqual(resolve_one({**host, "version": version}, self.CVE, [rec])["status"], want, version)

    def test_no_single_release_build_at_or_after_the_fix_no_record(self):
        for src in (None, sources(), sources(("openssl", "3.4.9-1", "")), sources(("openssl", "3.5.1-1", ""), ("openssl", "3.5.2-1", ""))):
            recs, skips = self.run_one(src)
            self.assertFalse([r for r in recs.values() if r["stream"] == "13"])
            self.assertTrue(any(sk[2] == "13" and "release build" in sk[4] for sk in skips))

    def test_fix_after_the_release_uses_the_lowest_later_release_build(self):
        # Owner 2026-11-03 (option A kept as a fallback), real case CVE-2024-2408 bookworm php8.2: fixed in
        # unstable 8.2.18-1 after bookworm released with 8.2.5-2; lowest later bookworm build 8.2.20-1~deb12u1.
        url = "https://security-tracker.debian.org/tracker/CVE-2024-2408"
        page = ("<h2>Vulnerable and fixed packages</h2><table>" + self.ROW.format("php8.2", "bookworm", "8.2.35-1~deb12u1", "fixed")
                + "</table>data on fixed versions<table><tr><td>php8.2</td><td>source</td><td>(unstable)</td><td>8.2.18-1</td><td></td><td></td><td></td></tr></table>")
        hist = {"result": [{"version": v} for v in ("8.2.35-1~deb12u1", "8.2.20-1~deb12u1", "8.2.7-1~deb12u1", "8.2.18-1", "8.2.5-2")]}
        snap = FakeSnap({url: page.encode(), "https://snapshot.debian.org/mr/package/php8.2/": json.dumps(hist).encode(),
                         "https://snapshot.debian.org/archive/debian/20230611T000000Z/dists/bookworm/main/source/Sources.xz": sources(("php8.2", "8.2.5-2", ""))})
        out = build.Out("2026-11-03")
        feeds.debian(snap, "CVE-2024-2408", "php", out, {})
        (r,) = out.records[("CVE-2024-2408", "php")].values()
        self.assertEqual((r["fixed"], r["origin"]), ("8.2.20-1~deb12u1", r"^8\.2\.\d+-\d+[~+]deb12u\d+$"))

    def test_vulnerable_with_no_fixed_version_for_the_release_gives_not_fixed(self):
        # Part 1 C1, real case: bookworm ships vulnerable builds; only unstable has a fix (3.5.0-1, unimportant).
        recs, _ = self.run_one(sources(("openssl", "3.5.1-1", "")))
        r = next(r for r in recs.values() if r["stream"] == "12")
        self.assertEqual((r["status"], r["branch"], r["package"], r["evidence_url"]), ("not-fixed", "3.0", "libssl3", self.URL))
        self.assertNotIn("fixed", r)

    def test_vulnerable_on_two_branches_no_record(self):
        out = build.Out("2026-11-03")
        page = self.page().replace(b"3.0.22-1~deb12u2", b"3.5.1-1~deb12u1")
        feeds.debian(FakeSnap({self.URL: page, self.SRC: sources(("openssl", "3.5.1-1", ""))}), self.CVE, "openssl", out, {})
        self.assertFalse([r for r in out.records[(self.CVE, "openssl")].values() if r["stream"] == "12"])
        self.assertTrue(any(sk[4].startswith("vulnerable in bookworm, but not one branch") for sk in out.skips))


class TestNotAffected(unittest.TestCase):
    # Owner, 2026-11-02: a vendor's stated "not affected" gives a record.
    ROW = "<tr><td>{}</td><td>{}</td><td>{}</td><td>fixed</td></tr>"
    URL = "https://security-tracker.debian.org/tracker/CVE-2024-0001"

    def deb(self, *rows):
        page = ("<h2>Vulnerable and fixed packages</h2><table>" + "".join(self.ROW.format(*r) for r in rows)
                + "</table>data on fixed versions<table><tr><td>openssl</td><td>source</td><td>bookworm</td>"
                "<td>(not affected)</td><td></td><td></td><td></td></tr></table>")
        out = build.Out("2026-11-02")
        feeds.debian(FakeSnap({self.URL: page.encode()}), "CVE-2024-0001", "openssl", out, {})
        return out

    def test_debian_not_affected_gives_a_record_for_the_releases_own_builds(self):
        out = self.deb(("openssl", "bookworm", "3.0.17-1~deb12u2"), ("", "bookworm (security)", "3.0.17-1~deb12u3"))
        (r,) = out.records[("CVE-2024-0001", "openssl")].values()
        self.assertEqual((r["status"], r["branch"], r["origin"], r["package"], r["evidence_url"]),
                         ("not-affected", "3.0", r"^3\.0\.\d+-\d+([~+]deb12u\d+)?$", "libssl3", self.URL))
        self.assertNotIn("fixed", r)

    def test_debian_not_affected_covers_the_releases_plain_build(self):
        # Part 1 B2, owner 2026-11-03: trixie's release build 3.5.1-1 read unknown for not-affected records.
        out = self.deb(("openssl", "bookworm", "3.0.9-1"), ("", "bookworm (security)", "3.0.17-1~deb12u3"))
        (r,) = out.records[("CVE-2024-0001", "openssl")].values()
        self.assertTrue(re.search(r["origin"], "3.0.9-1") and re.search(r["origin"], "3.0.17-1~deb12u3"))
        self.assertFalse(re.search(r["origin"], "3.0.9-1+thirdparty1") or re.search(r["origin"], "1:3.0.9-1"))

    def test_debian_not_affected_on_two_branches_or_outside_the_format_gives_no_record(self):
        for rows in ([("openssl", "bookworm", "3.0.17-1~deb12u2"), ("", "bookworm (security)", "3.5.1-1~deb12u1")],
                     [("openssl", "bookworm", "3.0.9-1+thirdparty1")]):
            out = self.deb(*rows)
            self.assertFalse(out.records.get(("CVE-2024-0001", "openssl")))
            self.assertTrue(any(sk[4].startswith("not affected, but bookworm ships") for sk in out.skips))

    def rh(self, statuses, module="php"):
        url = "https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-0001.json"
        doc = {"vulnerabilities": [{"product_status": statuses}]}
        out = build.Out("2026-11-02")
        feeds.rhel(FakeSnap({url: json.dumps(doc).encode()}), "CVE-2024-0001", module, out, {})
        return out

    def test_rhel_not_affected_only_where_the_module_stream_names_the_branch(self):
        out = self.rh({"known_not_affected": ["red_hat_enterprise_linux_9:php::php:8.2", "red_hat_enterprise_linux_9:php-cli::php:8.3",
                                              "red_hat_enterprise_linux_9:php", "red_hat_enterprise_linux_8:php::php:8.1"]})
        (r,) = [x for x in out.records[("CVE-2024-0001", "php")].values() if x["branch"] != "8.0"]
        self.assertEqual((r["status"], r["branch"], r["evidence_url"]),
                         ("not-affected", "8.2", "https://access.redhat.com/security/cve/CVE-2024-0001"))
        self.assertTrue(re.search(r["origin"], "8.2.35-1.module+el9.8.0+25111+a1450321"))
        self.assertFalse(re.search(r["origin"], "8.3.1-1.module+el9.8.0+25111+a1450321"))
        self.assertFalse(re.search(r["origin"], "8.2.35-1.el9.remi"))
        self.assertFalse(out.skips)
        # Owner, 2026-11-04: the plain package's statement is one record on branch 8.0, its origin the plain el9 build.
        (plain,) = [x for x in out.records[("CVE-2024-0001", "php")].values() if x["branch"] == "8.0"]
        self.assertEqual(plain["status"], "not-affected")
        self.assertTrue(re.search(plain["origin"], "8.0.30-8.el9_8.1"))
        self.assertFalse(re.search(plain["origin"], "8.2.35-1.module+el9.8.0+25111+a1450321"))

    def test_rhel_affected_module_stream_gives_a_not_fixed_record(self):
        # Review 8 F2: real case CVE-2025-1218, known_affected for php:8.2, 8.3 and 8.4, no fix.
        out = self.rh({"known_affected": ["red_hat_enterprise_linux_9:php::php:8.2", "red_hat_enterprise_linux_9:php::php:8.3",
                                          "red_hat_enterprise_linux_9:php::php:8.4", "red_hat_enterprise_linux_9:php"]})
        recs = out.records[("CVE-2024-0001", "php")]
        self.assertEqual(sorted((r["branch"], r["status"]) for r in recs.values()),
                         [("8.2", "not-fixed"), ("8.3", "not-fixed"), ("8.4", "not-fixed")])
        self.assertTrue(all("origin" not in r and "fixed" not in r for r in recs.values()))
        # the plain php statement is not applied: module streams share the package name
        self.assertIn(("CVE-2024-0001", "rhel", "9", "php", "affected, no fix: the plain php package shares its name with module streams"), out.skips)

    def test_rhel_openssl_statements_give_one_record_for_the_release(self):
        # Owner, 2026-11-03 (Part 1 C1, real case CVE-2024-13176, "Fix deferred"): affected, no fix gives not-fixed.
        out = self.rh({"known_affected": ["red_hat_enterprise_linux_9:openssl-libs"]}, "openssl")
        (r,) = out.records[("CVE-2024-0001", "openssl")].values()
        self.assertEqual((r["status"], r["branch"], r["package"], r["evidence_url"]),
                         ("not-fixed", "*", "openssl-libs", "https://access.redhat.com/security/cve/CVE-2024-0001"))
        out = self.rh({"known_not_affected": ["red_hat_enterprise_linux_9:openssl-libs"]}, "openssl")
        (r,) = out.records[("CVE-2024-0001", "openssl")].values()
        self.assertEqual((r["status"], r["branch"], r["origin"]), ("not-affected", "*", r"^1:\d+\.\d+\.\d+-\d+\.el9(_\d+)?(\.\d+)*$"))

    def test_rhel_plain_php_fix_is_on_branch_8_0(self):
        # Owner, 2026-11-04 (security review of 0.1.5, finding 1): branch "*" only for openssl-libs.
        from stillmapped.resolve import resolve_one, validate_record
        from stillmapped.vercmp import branch
        url = "https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-0001.json"
        pid = "Red Hat Enterprise Linux AppStream (v. 9):php-0:8.0.30-1.el9_2.x86_64"
        doc = {"product_tree": {"branches": [{"product": {"name": "Red Hat Enterprise Linux AppStream (v. 9)", "product_id": "Red Hat Enterprise Linux AppStream (v. 9)"}}]},
               "vulnerabilities": [{"product_status": {"fixed": [pid]},
                                    "remediations": [{"category": "vendor_fix", "url": "https://access.redhat.com/errata/RHSA-2026:1", "product_ids": [pid]}]}]}
        out = build.Out("2026-11-04")
        feeds.rhel(FakeSnap({url: json.dumps(doc).encode()}), "CVE-2024-0001", "php", out, {})
        (r,) = out.records[("CVE-2024-0001", "php")].values()
        self.assertEqual((r["branch"], r["fixed"]), ("8.0", "8.0.30-1.el9_2"))
        rec = {**r, "cve": "CVE-2024-0001", "module": "php"}
        self.assertEqual(validate_record(rec), [])
        host = {"source": "rpm", "vendor": "rhel", "stream": "9", "package": "php", "scheme": "vercmp-rpm", "where": "php", "module": "php", "db": "host"}
        for version, want in (("8.0.30-8.el9_8.1", "fixed"), ("8.0.27-1.el9", "not-fixed"), ("8.3.19-1.el9", "unknown")):
            got = resolve_one({**host, "version": version, "branch": branch(version)}, "CVE-2024-0001", [rec])["status"]
            self.assertEqual(got, want, version)

    def test_rhel_openssl_fix_compares_across_rebases(self):
        # Part 1 B3 and C, real cases: CVE-2024-12797 fixed in 1:3.2.2-6.el9_5.1; CVE-2025-9230 in 1:3.5.1-4.el9_7.
        from stillmapped.resolve import resolve_one
        url = "https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-0001.json"
        host = {"source": "rpm", "vendor": "rhel", "stream": "9", "package": "openssl-libs", "scheme": "vercmp-rpm",
                "where": "openssl-libs", "module": "openssl", "db": "host"}
        for fix, cases in (("1:3.2.2-6.el9_5.1", (("1:3.5.8-2.el9_8", "fixed"), ("1:3.2.2-6.el9_5.1", "fixed"), ("1:3.0.7-17.el9_2", "not-fixed"))),
                           ("1:3.5.1-4.el9_7", (("1:3.5.8-2.el9_8", "fixed"), ("1:3.2.2-6.el9_5.1", "not-fixed"),
                                                ("1:3.5.8-2.el9_8.alma", "unknown"), ("3.5.8-2.el9_8", "not-fixed")))):
            name, ver = fix.split(":")[1].rsplit("-", 1)[0], fix.split(":")[1].rsplit("-", 1)[1]
            pid = f"Red Hat Enterprise Linux BaseOS (v. 9):openssl-libs-1:{name}-{ver}.x86_64"
            doc = {"product_tree": {"branches": [{"product": {"name": "Red Hat Enterprise Linux BaseOS (v. 9)", "product_id": "Red Hat Enterprise Linux BaseOS (v. 9)"}}]},
                   "vulnerabilities": [{"product_status": {"fixed": [pid]},
                                        "remediations": [{"category": "vendor_fix", "url": "https://access.redhat.com/errata/RHSA-2026:1", "product_ids": [pid]}]}]}
            out = build.Out("2026-11-03")
            feeds.rhel(FakeSnap({url: json.dumps(doc).encode()}), "CVE-2024-0001", "openssl", out, {})
            (r,) = out.records[("CVE-2024-0001", "openssl")].values()
            self.assertEqual((r["branch"], r["fixed"]), ("*", fix))
            rec = {**r, "cve": "CVE-2024-0001", "module": "openssl"}
            for version, want in cases:
                from stillmapped.vercmp import branch
                got = resolve_one({**host, "version": version, "branch": branch(version)}, "CVE-2024-0001", [rec])["status"]
                self.assertEqual(got, want, (fix, version))

    def test_not_affected_and_fixed_for_one_build_give_no_record(self):
        out = build.Out("2026-11-02")
        rec = {"vendor": "debian", "stream": "12", "package": "libssl3", "branch": "3.0", "evidence_url": self.URL}
        out.add("CVE-2024-0001", "openssl", {**rec, "status": "not-affected", "origin": r"^3\.0\.\d+-\d+~deb12u\d+$"})
        out.add("CVE-2024-0001", "openssl", {**rec, "status": "fixed", "match": "vercmp-deb", "fixed": "3.0.14-1~deb12u2",
                                             "origin": r"^3\.0\.\d+-\d+~deb12u\d+$"})
        self.assertFalse(out.records[("CVE-2024-0001", "openssl")])


class TestOracle(unittest.TestCase):
    def test_evidence_url_compared_as_the_records_own_cve_page(self):
        rec = {"vendor": "debian", "stream": "12", "package": "php8.2", "branch": "8.2", "status": "fixed",
               "evidence_url": "https://security-tracker.debian.org/tracker/CVE-2026-0001"}
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "hand.json"), "w") as fh:
                json.dump({"cves": ["CVE-2026-0001", "CVE-2026-0002"], "records": [rec]}, fh)
            for cve, url in (("CVE-2026-0001", rec["evidence_url"]), ("CVE-2026-0002", rec["evidence_url"][:-1] + "2")):
                with open(os.path.join(d, f"{cve}.json"), "w") as fh:
                    json.dump({"records": [{**rec, "evidence_url": url}]}, fh)
            self.assertEqual(build.oracle(d, os.path.join(d, "hand.json")), ([], []))
            with open(os.path.join(d, "CVE-2026-0002.json"), "w") as fh:
                json.dump({"records": [rec]}, fh)  # the other CVE's page is a difference
            self.assertEqual(len(build.oracle(d, os.path.join(d, "hand.json"))[0]), 1)


class FakeSnap:
    def __init__(self, pages):
        self.pages = pages

    def get(self, url, body=None):
        return self.pages.get(url)


def osv(id_, eco, name, fixed, **kw):
    return {"id": id_, "affected": [{"package": {"ecosystem": eco, "name": name},
                                     "ranges": [{"events": [{"introduced": "0"}, {"fixed": fixed}]}]}], **kw}


class TestUbuntu(unittest.TestCase):
    CVE, ECO = "CVE-2026-0001", "Ubuntu:24.04:LTS"

    def run_one(self, usns, fixed="8.3.6-0ubuntu0.24.04.9"):
        rec = osv(f"UBUNTU-{self.CVE}", self.ECO, "php8.3", fixed, related=sorted(usns))
        snap = FakeSnap({f"https://api.osv.dev/v1/vulns/{u}": json.dumps(v).encode() for u, v in usns.items()})
        out = build.Out("2026-10-30")
        feeds.ubuntu(snap, {"24.04": [rec]}, self.CVE, "php", out)
        return out

    def test_usn_read_by_id_and_named_by_ubuntu_id(self):
        # The package query left this USN out, and it names the CVE only as UBUNTU-CVE-...
        out = self.run_one({"USN-8336-1": osv("USN-8336-1", self.ECO, "php8.3", "8.3.6-0ubuntu0.24.04.9",
                                              upstream=[f"UBUNTU-{self.CVE}"])})
        (r,) = out.records[(self.CVE, "php")].values()
        self.assertEqual(r["evidence_url"], "https://ubuntu.com/security/notices/USN-8336-1")

    def test_highest_of_cve_record_and_usns_with_its_own_usn(self):
        # Owner's rule: a later USN with a higher fix wins, and the receipt is that USN.
        out = self.run_one({"USN-1-1": osv("USN-1-1", self.ECO, "php8.3", "8.3.6-0ubuntu0.24.04.9", upstream=[self.CVE]),
                            "USN-1-2": osv("USN-1-2", self.ECO, "php8.3", "8.3.6-0ubuntu0.24.04.10", upstream=[self.CVE])})
        (r,) = out.records[(self.CVE, "php")].values()
        self.assertEqual((r["fixed"], r["evidence_url"][-7:]), ("8.3.6-0ubuntu0.24.04.10", "USN-1-2"))

    def test_no_usn_no_record(self):
        out = self.run_one({})
        self.assertFalse(out.records)
        self.assertTrue(any("no USN carries" in sk[4] for sk in out.skips))

    def test_libcrypto_binary_must_be_the_releases_own(self):
        # Real case CVE-2023-5363: Canonical lists noble's fix in libssl3 3.0.10-1ubuntu2.1, a pre-release
        # binary; noble ships libssl3t64. A record for libssl3 made the CVE judged and unknown on every noble host.
        rec = osv("UBUNTU-CVE-2023-5363", self.ECO, "openssl", "3.0.10-1ubuntu2.1",
                  related=["USN-1-1"])
        rec["affected"][0]["ecosystem_specific"] = {"binaries": [{"binary_name": "libssl3", "binary_version": "3.0.10-1ubuntu2.1"}]}
        usn = osv("USN-1-1", self.ECO, "openssl", "3.0.10-1ubuntu2.1", upstream=["CVE-2023-5363"])
        out = build.Out("2026-11-03")
        feeds.ubuntu(FakeSnap({"https://api.osv.dev/v1/vulns/USN-1-1": json.dumps(usn).encode()}), {"24.04": [rec]}, "CVE-2023-5363", "openssl", out)
        self.assertFalse(out.records)
        self.assertTrue(any("no single libcrypto binary" in sk[4] for sk in out.skips))

    def test_no_usn_canonical_cve_record_gives_the_fix(self):
        # Owner, 2026-11-03 (Part 1 C1, real case CVE-2026-7258 noble 8.3.6-0ubuntu0.24.04.9): no USN carries the
        # fix; Canonical's CVE JSON must say released at the same version, then its CVE page is the evidence.
        for status, version, want in (("released", "8.3.6-0ubuntu0.24.04.9", True), ("released", "8.3.6-0ubuntu0.24.04.8", False),
                                      ("needed", "", False)):
            rec = osv(f"UBUNTU-{self.CVE}", self.ECO, "php8.3", "8.3.6-0ubuntu0.24.04.9")
            js = {"packages": [{"name": "php8.3", "statuses": [{"release_codename": "noble", "status": status, "description": version}]}]}
            out = build.Out("2026-11-03")
            feeds.ubuntu(FakeSnap({f"https://ubuntu.com/security/cves/{self.CVE}.json": json.dumps(js).encode()}),
                         {"24.04": [rec]}, self.CVE, "php", out)
            recs = list(out.records.get((self.CVE, "php"), {}).values())
            self.assertEqual(bool(recs), want, status + version)
            if want:
                self.assertEqual((recs[0]["fixed"], recs[0]["evidence_url"]), (version, f"https://ubuntu.com/security/{self.CVE}"))


class TestUpstream(unittest.TestCase):
    def test_receipt_names_the_records_own_release(self):
        # The first item naming the CVE announced 8.2.35 only; it must not become the 8.5 receipt.
        a = "https://www.php.net/archive/2026.php#2026-10-21-"
        php = {"sections": [("8.5.12", "Fixed GHSA-aaaa-bbbb-cccc"), ("8.2.35", "Fixed GHSA-aaaa-bbbb-cccc")],
               "releases": {"8.5.12": {"tags": ["security"]}, "8.2.35": {"tags": ["security"]}}, "eol": {},
               "news": [((2026, 10, 21, 1), a + "1", "PHP 8.2.35 Released! fixes CVE-2026-0001"),
                        ((2026, 10, 21, 2), a + "2", "PHP 8.5.12 Released! fixes CVE-2026-0001"),
                        ((2026, 10, 21, 5), a + "5", "Advisory: PHP 8.5.12 and 8.2.35 fix CVE-2026-0001 ( GHSA-aaaa-bbbb-cccc )")]}
        out = build.Out("2026-10-30")
        feeds.upstream(php, "CVE-2026-0001", out)
        self.assertEqual({r["branch"]: r["evidence_url"][-1] for r in out.records[("CVE-2026-0001", "php")].values()},
                         {"8.2": "5", "8.5": "5"})

    def test_refix_in_a_later_release_wins(self):
        # Owner's rule: CVE-2024-4577 is listed in 8.3.8 and 8.3.12; the record says 8.3.12.
        php = {"sections": [("8.3.12", "CVE-2024-4577"), ("8.3.8", "CVE-2024-4577")],
               "releases": {"8.3.12": {"tags": ["security"]}, "8.3.8": {"tags": ["security"]}}, "eol": {},
               "news": [((2024, 9, 26, 1), "https://www.php.net/archive/2024.php#2024-09-26-1", "PHP 8.3.12 Released!")]}
        out = build.Out("2026-10-30")
        feeds.upstream(php, "CVE-2024-4577", out)
        self.assertEqual([r["fixed"] for r in out.records[("CVE-2024-4577", "php")].values()], ["8.3.12"])


class TestSnapshot(unittest.TestCase):
    def test_offline_build_refuses_a_changed_file(self):
        with tempfile.TemporaryDirectory() as d:
            snap = Snapshot(d, online=True)
            with patch("urllib.request.urlopen") as u:
                u.return_value.__enter__.return_value.status = 200
                u.return_value.__enter__.return_value.read.return_value = b"data"
                self.assertEqual(snap.get("https://example.invalid/x"), b"data")
            snap.save()
            off = Snapshot(d)
            self.assertEqual(off.get("https://example.invalid/x"), b"data")
            with self.assertRaises(KeyError):
                off.get("https://example.invalid/not-fetched")
            with open(os.path.join(d, off.manifest["entries"]["https://example.invalid/x"]["file"]), "wb") as fh:
                fh.write(b"changed")
            with self.assertRaises(ValueError):
                off.get("https://example.invalid/x")


SNAPS = sorted(glob.glob(os.path.join(os.path.dirname(os.path.dirname(__file__)), "snapshots", "*", "manifest.json")))


@unittest.skipUnless(SNAPS, "no snapshot: run python3 -m tools.sync fetch")
class TestRealSnapshot(unittest.TestCase):
    def test_same_snapshot_same_bytes(self):
        snap = os.path.dirname(SNAPS[-1])
        outs = []
        for _ in range(2):
            with tempfile.TemporaryDirectory() as d:
                build.write(build.run(Snapshot(snap)), d)
                outs.append({f: pathlib.Path(d, f).read_bytes() for f in sorted(os.listdir(d))})
        self.assertEqual(outs[0], outs[1])

    def test_oracle_reproduces_the_hand_records(self):
        with tempfile.TemporaryDirectory() as d:
            build.write(build.run(Snapshot(os.path.dirname(SNAPS[-1]))), d)
            hand = os.path.join(os.path.dirname(__file__), "..", "hand", "php2shell.json")
            self.assertEqual(build.oracle(d, hand)[0], [])


if __name__ == "__main__":
    unittest.main()
