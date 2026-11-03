import json
import unittest
from unittest.mock import MagicMock, patch

from stillmapped.resolve import exit_code, load_records, resolve, resolve_one, validate_record
from stillmapped.vercmp import branch

CVE = "CVE-TEST-0001"

# Fixture records only. Real records live in stillmapped/data/ and must be
# verified against the vendor's own advisory.
UBUNTU_2404 = r"^8\.3\.6-0ubuntu0\.24\.04\.\d+$"
RECORDS = [
    {"cve": CVE, "vendor": "ubuntu", "stream": "24.04", "package": "php8.3", "branch": "8.3",
     "match": "vercmp-deb", "fixed": "8.3.6-0ubuntu0.24.04.13", "status": "fixed",
     "origin": UBUNTU_2404, "evidence_url": "https://example.invalid/usn", "checked": "2026-10-21"},
    {"cve": CVE, "vendor": "sury", "stream": "*", "package": "php8.5", "branch": "8.5",
     "match": "vercmp-deb", "fixed": "8.5.12-1", "status": "fixed",
     "origin": r"^8\.5\.\d+-\d+(\+\S+)?$", "evidence_url": "https://example.invalid/sury", "checked": "2026-10-21"},
    {"cve": CVE, "vendor": "cpanel", "stream": "*", "package": "ea-php74", "branch": "7.4",
     "status": "unknown", "note": "backported without a version change",
     "evidence_url": "https://example.invalid/ea4", "checked": "2026-10-21"},
    {"cve": CVE, "vendor": "amzn", "stream": "2023", "package": "php", "branch": "8.4",
     "status": "not-fixed",
     "evidence_url": "https://example.invalid/al", "checked": "2026-10-21"},
    {"cve": CVE, "vendor": "upstream", "stream": "*", "package": "php", "branch": "8.5",
     "match": "upstream", "fixed": "8.5.12", "status": "fixed",
     "evidence_url": "https://example.invalid/php", "checked": "2026-10-21"},
    {"cve": CVE, "vendor": "rhel", "stream": "9", "package": "php", "branch": "8.2",
     "match": "vercmp-rpm", "fixed": "8.2.35-1.module+el9.8.0+25111+a1450321", "status": "fixed",
     "origin": r"^8\.2\.\d+-\d+\.module\+el9\.\d+\.\d+\+\d+\+[0-9a-f]{8}$", "evidence_url": "https://example.invalid/rhsa", "checked": "2026-10-21"},
]
RECORDS = [{**r, "module": "php"} for r in RECORDS]
UPSTREAM_85 = RECORDS[4]


def b(vendor, stream, package, version, scheme):
    return {"source": "test", "vendor": vendor, "stream": stream, "package": package,
            "branch": branch(version), "version": version, "scheme": scheme, "where": "test",
            "module": "php", "db": "host"}


def up(version):
    return b("upstream", "*", "php", version, "upstream")


class TestResolveOne(unittest.TestCase):
    def check(self, build, want):
        self.assertEqual(resolve_one(build, CVE, RECORDS)["status"], want)

    def test_fixed_and_not_fixed(self):
        self.check(b("ubuntu", "24.04", "php8.3", "8.3.6-0ubuntu0.24.04.13", "vercmp-deb"), "fixed")
        self.check(b("ubuntu", "24.04", "php8.3", "8.3.6-0ubuntu0.24.04.12", "vercmp-deb"), "not-fixed")

    def test_wildcard_stream(self):
        self.check(b("sury", "*", "php8.5", "8.5.12-1+0~20261021.1+debian12~1.gbp1", "vercmp-deb"), "fixed")
        self.check(b("sury", "*", "php8.5", "8.5.11-1+0~20261001.1+debian12~1.gbp1", "vercmp-deb"), "not-fixed")

    def test_unresolvable_is_unknown_never_fixed(self):
        self.check(b("cpanel", "*", "ea-php74", "7.4.33-12.el9", "vercmp-rpm"), "unknown")

    def test_vendor_not_shipped(self):
        self.check(b("amzn", "2023", "php", "8.4.26-1.amzn2023", "vercmp-rpm"), "not-fixed")

    def test_no_record_is_unknown(self):
        self.check(b("ubuntu", "22.04", "php8.1", "8.1.2-1ubuntu2.28", "vercmp-deb"), "unknown")

    def test_other_ubuntu_stream_does_not_match(self):
        # A 24.04 record must never be applied to a 26.04 build.
        self.check(b("ubuntu", "26.04", "php8.3", "8.3.99-1", "vercmp-deb"), "unknown")

    def test_scheme_mismatch_is_unknown(self):
        self.check(b("ubuntu", "24.04", "php8.3", "8.3.6-0ubuntu0.24.04.13", "vercmp-rpm"), "unknown")

    def test_garbage_version_is_unknown(self):
        self.check(b("ubuntu", "24.04", "php8.3", "x:junk", "vercmp-deb"), "unknown")

    def test_upstream(self):
        self.check(up("8.5.12"), "fixed")
        self.check(up("8.5.11"), "not-fixed")

    def test_upstream_prerelease_is_unknown(self):
        # Audit: 8.5.12RC1 and friends used to sort as >= 8.5.12.
        for v in ("8.5.12RC1", "8.5.12-dev", "8.5.12junk", "8.5.13RC1"):
            with self.subTest(v=v):
                self.check(up(v), "unknown")

    def test_conflicting_records_are_unknown_in_any_order(self):
        # Audit: the first matching record used to win.
        later = {**UPSTREAM_85, "fixed": "8.5.13"}
        for order in ([UPSTREAM_85, later], [later, UPSTREAM_85]):
            with self.subTest(first=order[0]["fixed"]):
                self.assertEqual(resolve_one(up("8.5.12"), CVE, order)["status"], "unknown")

    def test_origin_gates_fixed_only(self):
        # Audit: 8.3.6-99acme1 on Ubuntu compared above the fix and passed.
        # Review: so did PPA rebuilds and an epoch, while "ubuntu" was the origin.
        status = lambda v: resolve_one(b("ubuntu", "24.04", "php8.3", v, "vercmp-deb"), CVE, RECORDS)["status"]
        for v in ("8.3.6-99acme1", "8.3.20-1~ubuntu24.04.1", "8.3.7-0ubuntu0.24.04.1~ppa1",
                  "1:8.3.0-0ubuntu1", "1:8.3.6-0ubuntu0.24.04.13"):
            with self.subTest(v=v):
                self.assertEqual(status(v), "unknown")
        self.assertEqual(status("8.3.6-0ubuntu0.24.04.13"), "fixed")
        self.assertEqual(status("8.3.6-0ubuntu0.24.04.12"), "not-fixed")

    def test_identical_duplicates_still_resolve(self):
        self.assertEqual(resolve_one(up("8.5.12"), CVE, [UPSTREAM_85, dict(UPSTREAM_85)])["status"],
                         "fixed")

    def test_other_branch_never_matches(self):
        # RHEL ships 8.1/8.2/8.3 module streams all named "php". An 8.3 build
        # compares higher than the 8.2 fix, so it must not match that record.
        self.check(b("rhel", "9", "php", "8.2.35-1.module+el9.8.0+25111+a1450321", "vercmp-rpm"), "fixed")
        self.check(b("rhel", "9", "php", "8.2.30-1.module+el9.7.0+24000+a1450321", "vercmp-rpm"), "not-fixed")
        self.check(b("rhel", "9", "php", "8.3.15-1.module+el9.6.0+23000+bbbbbbbb", "vercmp-rpm"), "unknown")


class TestTrust(unittest.TestCase):
    def test_every_result_names_its_evidence(self):
        # Codex Security finding 1: no verification feature; the evidence is named instead.
        base = b("ubuntu", "24.04", "php8.3", "8.3.6-0ubuntu0.24.04.13", "vercmp-deb")
        for build, want in (({**base, "source": "dpkg"}, "host-pkgdb"), ({**base, "source": "rpm"}, "host-pkgdb"),
                            ({**base, "source": "dpkg", "db": "container"}, "container-pkgdb"),
                            ({**base, "source": "docker"}, "image-metadata"),
                            ({**base, "source": "directadmin"}, "root-owned-source"),
                            ({**base, "source": "source"}, "root-owned-source")):
            with self.subTest(source=build["source"], db=build["db"]):
                self.assertEqual(resolve_one(build, CVE, RECORDS)["trust"], want)
                self.assertEqual(resolve_one(build, "CVE-NONE", RECORDS)["trust"], want)  # unknown too


class TestMutationSurvivors(unittest.TestCase):
    """Deep verification Part 4: a named test for each surviving mutant M3 to M5, M7."""

    def test_tilde_sorts_before_the_end_of_the_version(self):
        # M3: with "~" equal to the end, a pre-release 1.0~rc1 compared equal to 1.0 and read fixed.
        from stillmapped.vercmp import compare_deb
        self.assertEqual(compare_deb("1.0~rc1", "1.0"), -1)
        self.assertEqual(compare_deb("8.3.6-0ubuntu0.24.04.13~ppa1", "8.3.6-0ubuntu0.24.04.13"), -1)
        rec = {**RECORDS[0], "origin": r"^8\.3\.6-0ubuntu0\.24\.04\.\d+(~\w+)?$"}
        pre = b("ubuntu", "24.04", "php8.3", "8.3.6-0ubuntu0.24.04.13~rc1", "vercmp-deb")
        self.assertEqual(resolve_one(pre, CVE, [rec])["status"], "not-fixed")

    def test_exact_stream_and_branch_beat_wildcards(self):
        # M4: with the preference inverted, a wildcard record overruled the exact one.
        exact = {**RECORDS[5], "status": "not-fixed"}
        exact.pop("fixed"), exact.pop("match"), exact.pop("origin")
        wild = {**RECORDS[5], "stream": "*"}
        build = b("rhel", "9", "php", "8.2.40-1.module+el9.8.0+25200+b2c3d4e5", "vercmp-rpm")
        self.assertEqual(resolve_one(build, CVE, [wild, exact])["status"], "not-fixed")
        self.assertEqual(resolve_one(build, CVE, [wild])["status"], "fixed")
        anybranch = {**wild, "stream": "9", "branch": "*", "status": "not-fixed"}
        anybranch.pop("fixed"), anybranch.pop("match"), anybranch.pop("origin")
        self.assertEqual(resolve_one(build, CVE, [anybranch, RECORDS[5]])["status"], "fixed")
        self.assertEqual(resolve_one(build, CVE, [anybranch])["status"], "not-fixed")

    def test_a_misspelled_status_is_a_problem(self):
        # M5: without the check, a record with status "fixd" resolved like a fixed one.
        self.assertIn("bad status 'fixd'", validate_record({**RECORDS[0], "status": "fixd"}))
        self.assertIn("bad status 'FIXED'", validate_record({**RECORDS[0], "status": "FIXED"}))

    def test_epoch_must_be_ascii_digits(self):
        # M7: without isascii(), an Arabic-Indic digit epoch parsed as 1 and compared newer.
        from stillmapped.vercmp import compare_deb, compare_rpm, split_evr
        for bad in ("\u0661:8.2.35-1~deb12u1", "\uff11:8.2.35-1~deb12u1"):
            with self.subTest(bad=bad):
                self.assertRaises(ValueError, split_evr, bad)
                self.assertRaises(ValueError, compare_deb, bad, "8.2.35-1~deb12u1")
                self.assertRaises(ValueError, compare_rpm, bad, "8.2.35-1")

    def test_rhel_branch_wildcard_only_for_rhel(self):
        # Owner 2026-11-03: branch "*" is a RHEL package judged per release; any other vendor keeps branches.
        rhel = {**RECORDS[5], "branch": "*", "fixed": "1:3.2.2-6.el9_5.1", "origin": r"^1:\d+\.\d+\.\d+-\d+\.el9(_\d+)?(\.\d+)*$"}
        self.assertEqual(validate_record(rhel), [])
        self.assertIn("fixed version 8.3.6-0ubuntu0.24.04.13 is not on branch *", validate_record({**RECORDS[0], "branch": "*"}))


class TestBundledData(unittest.TestCase):
    def test_every_record_valid(self):
        records = load_records()
        self.assertTrue(records)
        for r in records:
            with self.subTest(vendor=r["vendor"], stream=r["stream"], package=r["package"], cve=r["cve"]):
                self.assertEqual(validate_record(r), [])

    def test_fixtures_valid(self):
        for r in RECORDS:
            with self.subTest(vendor=r["vendor"]):
                self.assertEqual(validate_record(r), [])

    def test_validator_requires_branch(self):
        bad = {k: v for k, v in RECORDS[5].items() if k != "branch"}
        self.assertIn("missing branch", validate_record(bad))

    def test_validator_rejects_fix_on_other_branch(self):
        # Audit: an 8.4.0 fix on an 8.5 record used to pass.
        bad = {**UPSTREAM_85, "fixed": "8.4.0"}
        self.assertIn("fixed version 8.4.0 is not on branch 8.5", validate_record(bad))

    def test_validator_rejects_impossible_date(self):
        for d in ("2026-99-99", "20261022", "2026-10-22T00:00", None):
            with self.subTest(d=d):
                self.assertIn("checked must be a real YYYY-MM-DD date",
                              validate_record({**UPSTREAM_85, "checked": d}))

    def test_validator_origin(self):
        self.assertIn("fixed version 8.3.6-0ubuntu0.24.04.13 doesn't match its own origin",
                      validate_record({**RECORDS[0], "origin": "debian"}))
        self.assertIn("bad origin pattern '('", validate_record({**RECORDS[0], "origin": "("}))
        self.assertEqual(validate_record(RECORDS[0]), [])
        self.assertIn("distro record needs an origin pattern anchored with ^ and $, without |",
                      validate_record({**RECORDS[0], "origin": "ubuntu"}))

    def test_validator_requires_origin_end_anchor(self):
        # Review 2 #11: RHEL's '^8\.2\.\d+-\d+\.module\+el9\.' accepted '...a1450321.thirdparty1'.
        rec = {**RECORDS[5], "origin": r"^8\.2\.\d+-\d+\.module\+el9\."}
        self.assertIn("distro record needs an origin pattern anchored with ^ and $, without |", validate_record(rec))
        rebuild = b("rhel", "9", "php", "8.2.35-1.module+el9.8.0+25111+a1450321.thirdparty1", "vercmp-rpm")
        self.assertEqual(resolve_one(rebuild, CVE, RECORDS)["status"], "unknown")
        self.assertEqual(resolve_one(rebuild, "CVE-2026-109618", load_records())["status"], "unknown")
        self.assertEqual(validate_record(UPSTREAM_85), [])  # upstream versions need no origin

    def test_validator_library_record_needs_soname(self):
        lib = {**RECORDS[0], "module": "openssl", "file": "libcrypto.so.3", "origin": UBUNTU_2404}
        self.assertEqual(validate_record(lib), [])
        for bad in (None, 3, "", "../libcrypto.so.3", "/usr/lib/libcrypto.so.3", "libcrypto*", ".hidden",
                    "libcrypto.so.3\n", "libcr\u00fdpto.so.3"):
            with self.subTest(file=bad):
                self.assertTrue(validate_record({**lib, "file": bad}))

    def test_validator_wrong_field_types_are_problems_not_exceptions(self):
        # Fuzz F3, minimal inputs: match {} raised TypeError (unhashable), fixed 1 raised
        # TypeError in branch(); load_records then stopped with exit 3.
        self.assertEqual(validate_record({**RECORDS[0], "match": {}}), ["match must be a string"])
        self.assertEqual(validate_record({**RECORDS[0], "fixed": 1}), ["fixed must be a string"])
        self.assertEqual(validate_record({**RECORDS[0], "origin": ["^x$"]}), ["origin must be a string"])

    def test_validator_origin_that_fails_to_compile_is_a_problem(self):
        # Fuzz F3: deeply nested groups raised RecursionError, which only re.error was caught for.
        deep = "^" + "(" * 100000 + ")" * 100000 + "$"
        self.assertIn(f"bad origin pattern {deep!r}", validate_record({**RECORDS[0], "origin": deep}))

    def test_validator_checks_not_affected_like_fixed(self):
        # Fuzz F4, minimal inputs: a not-affected record with origin "^[$", or with fixed {},
        # passed validation and then raised in resolve_one (re.error, TypeError).
        na = {k: v for k, v in RECORDS[0].items() if k not in ("fixed", "match")}
        na["status"] = "not-affected"
        self.assertEqual(validate_record(na), [])
        self.assertIn("bad origin pattern '^[$'", validate_record({**na, "origin": "^[$"}))
        self.assertEqual(validate_record({**na, "fixed": {}}), ["fixed must be a string"])

    def test_validator_rejects_fixed_version_with_empty_release(self):
        # Fuzz F8, minimal input: "1" vs "1-". compare_rpm calls them equal; rpm orders 1 before 1-.
        rec = {**RECORDS[5], "fixed": "8.2.35-", "origin": r"^8\.2\.\d+-.*$"}
        self.assertIn("fixed version 8.2.35- has an empty release", validate_record(rec))

    def test_validator_unknown_needs_note(self):
        bad = {k: v for k, v in RECORDS[2].items() if k != "note"}
        self.assertIn("unknown record needs a note saying why", validate_record(bad))

    def test_loader_refuses_invalid_data(self):
        # Audit: the loader used to accept records the validator rejects.
        source = MagicMock()
        source.name = "bad.json"
        bad = {k: v for k, v in UPSTREAM_85.items() if k not in ("cve", "branch")}
        source.read_text.return_value = json.dumps({"cves": [CVE], "records": [bad]})
        package = MagicMock()
        data = package.__truediv__.return_value
        data.is_dir.return_value = True
        data.iterdir.return_value = [source]
        with patch("stillmapped.resolve.resources.files", return_value=package):
            with self.assertRaisesRegex(ValueError, "bad.json: upstream/php .*missing branch"):
                load_records({CVE})

    def load(self, *docs):
        package = MagicMock()
        files = []
        for i, doc in enumerate(docs):
            f = MagicMock()
            f.name = f"d{i}.json"
            f.read_text.return_value = json.dumps(doc)
            files.append(f)
        package.__truediv__.return_value.iterdir.return_value = files
        with patch("stillmapped.resolve.resources.files", return_value=package):
            return load_records()

    def test_cve_in_two_modules_is_refused(self):
        # Review 3 #5: module[cve] kept the last file's module and hid the other module's builds.
        rec = {k: v for k, v in RECORDS[0].items() if k not in ("cve", "module")}
        lib = {**rec, "file": "libcrypto.so.3"}
        with self.assertRaisesRegex(ValueError, "also in a php data file"):
            self.load({"cves": [CVE], "records": [rec]}, {"module": "openssl", "cves": [CVE], "records": [lib]})

    def test_origin_with_alternation_is_refused(self):
        # Review 3 #6: "^...|.*$" passed the anchor check and matched any version.
        rec = {**RECORDS[0], "origin": r"^8\.3\.6-0ubuntu0\.24\.04\.\d+|.*$"}
        self.assertIn("distro record needs an origin pattern anchored with ^ and $, without |", validate_record(rec))

    def test_bundled_data_covers_the_hand_cves_without_duplicates(self):
        records = load_records()
        self.assertLessEqual({"CVE-2026-109618", "CVE-2026-109619"}, {r["cve"] for r in records})
        keys = [(r["cve"], r["vendor"], r["stream"], r["package"], r["branch"]) for r in records]
        self.assertEqual(len(keys), len(set(keys)))


class TestExitCode(unittest.TestCase):
    def report(self, builds, workers=(), problems=()):
        inv = {"builds": builds, "workers": list(workers), "problems": list(problems)}
        return resolve(inv, RECORDS, [CVE])

    def test_problem_makes_all_fixed_unknown(self):
        # Audit: a part of the host that couldn't be checked still exited 0.
        r = self.report([up("8.5.12")], problems=["no /proc"])
        self.assertEqual(exit_code(r), 2)
        self.assertEqual(exit_code(self.report([], problems=["dpkg unreadable"])), 2)

    def test_not_fixed_wins_over_problems(self):
        self.assertEqual(exit_code(self.report([up("8.5.11")], problems=["x"])), 1)

    def test_all_fixed(self):
        r = self.report([up("8.5.12")])
        self.assertEqual(exit_code(r), 0)

    def test_not_fixed_wins_over_unknown(self):
        r = self.report([up("8.5.11"),
                         b("cpanel", "*", "ea-php74", "7.4.33-12.el9", "vercmp-rpm")])
        self.assertEqual(exit_code(r), 1)

    def test_unknown(self):
        r = self.report([b("cpanel", "*", "ea-php74", "7.4.33-12.el9", "vercmp-rpm")])
        self.assertEqual(exit_code(r), 2)

    def test_stale_worker_fails_even_when_fixed(self):
        r = self.report([up("8.5.12")],
                        workers=[{"pid": "1", "exe": "/usr/sbin/php-fpm (deleted)", "stale": True}])
        self.assertEqual(exit_code(r), 1)

    def test_no_php_is_a_problem_not_a_pass(self):
        # Review: an empty host exited 0. Now checked per module of the CVEs asked.
        r = self.report([])
        self.assertEqual((r["problems"], exit_code(r)), (["no PHP build found"], 2))



# Owner, 2026-11-02: vendor "not affected" records, and the default run's
# "not judged" rule. Fixture records only.
DEB12_NA = {"cve": "CVE-TEST-0003", "module": "openssl", "vendor": "debian", "stream": "12", "package": "libssl3",
            "branch": "3.0", "file": "libcrypto.so.3", "status": "not-affected", "origin": r"^3\.0\.\d+-\d+~deb12u\d+$",
            "evidence_url": "https://security-tracker.debian.org/tracker/CVE-TEST-0003", "checked": "2026-11-02"}
DEB12_FIX = {**DEB12_NA, "cve": "CVE-TEST-0004", "status": "fixed", "match": "vercmp-deb", "fixed": "3.0.14-1~deb12u2"}
SSL = {"source": "dpkg", "vendor": "debian", "stream": "12", "package": "libssl3", "branch": "3.0",
       "version": "3.0.17-1~deb12u3", "scheme": "vercmp-deb", "where": "libssl3", "module": "openssl", "db": "host"}


class TestNotAffected(unittest.TestCase):
    def test_not_affected_record_resolves_not_affected_and_exits_0(self):
        r = resolve({"builds": [SSL], "workers": [], "problems": []}, [DEB12_NA], ["CVE-TEST-0003"])
        self.assertEqual([x["status"] for x in r["results"]], ["not-affected"])
        self.assertEqual(exit_code(r), 0)

    def test_not_affected_needs_the_vendors_own_build(self):
        odd = {**SSL, "version": "3.0.17-1+thirdparty1"}
        self.assertEqual(resolve_one(odd, "CVE-TEST-0003", [DEB12_NA])["status"], "unknown")
        self.assertEqual(resolve_one({**SSL, "branch": "3.5", "version": "3.5.1-1~deb12u1"}, "CVE-TEST-0003", [DEB12_NA])["status"], "unknown")

    def test_validator_not_affected_needs_anchored_origin_and_no_fixed_version(self):
        self.assertEqual(validate_record(DEB12_NA), [])
        for bad in ({**DEB12_NA, "origin": None}, {**DEB12_NA, "origin": r"^3\.0|.*$"}, {**DEB12_NA, "fixed": "3.0.1-1~deb12u1"}):
            self.assertTrue(validate_record(bad), bad)

    def test_not_affected_and_fixed_for_one_build_disagree(self):
        both = [DEB12_NA, {**DEB12_FIX, "cve": "CVE-TEST-0003"}]
        self.assertEqual(resolve_one(SSL, "CVE-TEST-0003", both)["status"], "unknown")

    def test_no_record_reason_names_the_module(self):
        reason = resolve_one(SSL, "CVE-TEST-0009", [DEB12_NA])["reason"]
        self.assertIn("(OpenSSL 3.0)", reason)
        self.assertNotIn("PHP", reason)


class TestDefaultRunNotJudged(unittest.TestCase):
    INV = {"builds": [SSL], "workers": [], "problems": []}
    CVES = ["CVE-TEST-0004", "CVE-TEST-0005", "CVE-TEST-0006"]
    # 0005 and 0006 have records for Ubuntu only.
    RECS = [DEB12_FIX, {**DEB12_FIX, "cve": "CVE-TEST-0005", "vendor": "ubuntu", "stream": "24.04"},
            {**DEB12_FIX, "cve": "CVE-TEST-0006", "vendor": "ubuntu", "stream": "24.04"}]

    def test_default_run_skips_cves_with_no_record_for_the_vendor_and_stream(self):
        r = resolve(self.INV, self.RECS, self.CVES, strict=False)
        self.assertEqual([(x["cve"], x["status"]) for x in r["results"]], [("CVE-TEST-0004", "fixed")])
        self.assertEqual(r["info"], ["2 CVEs: no vendor record for debian 12, not judged"])
        self.assertEqual(r["not_judged"], {"debian 12": ["CVE-TEST-0005", "CVE-TEST-0006"]})
        self.assertEqual(exit_code(r), 0)

    def test_named_cves_are_still_judged_unknown(self):
        r = resolve(self.INV, self.RECS, self.CVES, strict=True)
        self.assertEqual([x["status"] for x in r["results"]], ["fixed", "unknown", "unknown"])
        self.assertEqual((r["info"], exit_code(r)), ([], 2))

    def test_vendor_with_no_records_at_all_is_still_judged(self):
        # Fail closed: a distro the data does not cover must not exit 0 unchecked.
        fedora = {**SSL, "vendor": "fedora", "stream": "41", "version": "3.2.4-1.fc41", "scheme": "vercmp-rpm"}
        r = resolve({**self.INV, "builds": [fedora]}, self.RECS, self.CVES, strict=False)
        self.assertEqual([x["status"] for x in r["results"]], ["unknown"] * 3)
        self.assertEqual((r["info"], exit_code(r)), ([], 2))

    def test_record_for_another_package_or_branch_is_still_judged(self):
        r = resolve({**self.INV, "builds": [{**SSL, "branch": "3.5", "version": "3.5.1-1~deb12u1"}]}, self.RECS, ["CVE-TEST-0004"], strict=False)
        self.assertEqual(([x["status"] for x in r["results"]], exit_code(r)), (["unknown"], 2))

    def test_mapped_library_follows_the_same_rule(self):
        m = {"pid": "7", "path": "/usr/lib/libcrypto.so.3", "file": "libcrypto.so.3", "same": True, "build": SSL}
        r = resolve({**self.INV, "mappings": [m]}, self.RECS, self.CVES, strict=False)
        self.assertEqual(sorted(x["cve"] for x in r["results"]), ["CVE-TEST-0004", "CVE-TEST-0004"])
        self.assertEqual(r["not_judged"], {"debian 12": ["CVE-TEST-0005", "CVE-TEST-0006"]})


if __name__ == "__main__":
    unittest.main()
