import glob
import json
import os
import re
import tempfile
import unittest
from unittest.mock import patch

from phpfixed.vercmp import compare

from tools.sync import build, feeds, origin
from tools.sync.snap import Snapshot

DEB12, DEB13 = origin.debian("12"), origin.debian("13")

# Design note section 4: (templates, vendor fixed version, EOL final or None,
# expected origin, the vendor's next update, versions that must fail).
TABLE = [
    (DEB12, "8.2.35-1~deb12u1", None, r"^8\.2\.\d+-\d+~deb12u\d+$", "8.2.36-1~deb12u1",
     ["8.2.35-1~deb12u1+thirdparty1", "1:8.2.35-1~deb12u1", "8.2.35-1+deb12u1", "8.2.35-1~deb12u1+b1",
      "8.2.99-1+0~20261022.1+debian12~1.gbp", "8.3.1-1~deb12u1"]),
    (DEB13, "8.4.27-1~deb13u1", None, r"^8\.4\.\d+-\d+~deb13u\d+$", "8.4.28-1~deb13u1", ["8.4.27-1~deb12u1"]),
    (DEB12, "3.0.14-1~deb12u2", None, r"^3\.0\.\d+-\d+~deb12u\d+$", "3.0.22-1~deb12u2",
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
    (origin.RHEL, "1:3.0.7-28.el9_4", None, r"^1:3\.0\.\d+-\d+\.el9(_\d+)?(\.\d+)*$", "1:3.0.7-29.el9_5",
     ["2:3.0.7-28.el9_4", "3.0.7-28.el9_4", "1:3.0.7-28.el9_4.alma", "1:3.0.7-28.el9_4+custom1"]),
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

class TestDebianBeforeRelease(unittest.TestCase):
    def test_fixed_before_release_uses_lowest_shipped_version(self):
        # Owner 2026-10-30: fixed in 3.0.9-1 before bookworm; a host on the lower
        # shipped build 3.0.20-1~deb12u2 must read fixed, not a false alarm.
        cve, url = "CVE-2026-0002", "https://security-tracker.debian.org/tracker/CVE-2026-0002"
        row = "<tr><td>{}</td><td>{}</td><td>{}</td><td>fixed</td></tr>"
        page = ("<h2>Vulnerable and fixed packages</h2><table>" + row.format("openssl", "bookworm", "3.0.20-1~deb12u2")
                + row.format("", "bookworm (security)", "3.0.22-1~deb12u2") + "</table>data on fixed versions<table>"
                "<tr><td>openssl</td><td>source</td><td>(unstable)</td><td>3.0.9-1</td><td></td><td></td><td></td></tr></table>")
        out = build.Out("2026-10-30")
        feeds.debian(FakeSnap({url: page.encode()}), cve, "openssl", out, {})
        (r,) = out.records[(cve, "openssl")].values()
        self.assertEqual(r["fixed"], "3.0.20-1~deb12u2")
        self.assertGreaterEqual(compare("vercmp-deb", "3.0.20-1~deb12u2", r["fixed"]), 0)  # reads fixed
        self.assertTrue(re.match(r["origin"], "3.0.20-1~deb12u2"))
        self.assertEqual(feeds.highest("vercmp-deb", ["3.0.22-1~deb12u2", "3.0.20-1~deb12u2"], min), "3.0.20-1~deb12u2")


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
                outs.append({f: open(os.path.join(d, f), "rb").read() for f in sorted(os.listdir(d))})
        self.assertEqual(outs[0], outs[1])

    def test_oracle_reproduces_the_hand_records(self):
        with tempfile.TemporaryDirectory() as d:
            build.write(build.run(Snapshot(os.path.dirname(SNAPS[-1]))), d)
            hand = os.path.join(os.path.dirname(__file__), "..", "..", "..", "phpfixed", "data", "php2shell.json")
            self.assertEqual(build.oracle(d, hand)[0], [])


if __name__ == "__main__":
    unittest.main()
