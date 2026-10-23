import unittest

from phpfixed.collect import _branch
from phpfixed.resolve import exit_code, load_records, resolve, resolve_one, validate_record

CVE = "CVE-TEST-0001"

# Fixture records only. Real records live in phpfixed/data/ and must be
# verified against the vendor's own advisory.
RECORDS = [
    {"cve": CVE, "vendor": "ubuntu", "stream": "24.04", "package": "php8.3",
     "match": "vercmp-deb", "fixed": "8.3.6-0ubuntu0.24.04.13", "status": "fixed",
     "evidence_url": "https://example.invalid/usn", "checked": "2026-10-21"},
    {"cve": CVE, "vendor": "sury", "stream": "*", "package": "php8.5",
     "match": "vercmp-deb", "fixed": "8.5.12-1", "status": "fixed",
     "evidence_url": "https://example.invalid/sury", "checked": "2026-10-21"},
    {"cve": CVE, "vendor": "cpanel", "stream": "*", "package": "ea-php74",
     "match": "unresolvable", "fixed": None, "status": "fixed",
     "note": "backported without a version change",
     "evidence_url": "https://example.invalid/ea4", "checked": "2026-10-21"},
    {"cve": CVE, "vendor": "amzn", "stream": "2023", "package": "php",
     "match": "vercmp-rpm", "fixed": None, "status": "not-fixed",
     "evidence_url": "https://example.invalid/al", "checked": "2026-10-21"},
    {"cve": CVE, "vendor": "docker-official", "stream": "8.5", "package": "php", "branch": "8.5",
     "match": "upstream", "fixed": "8.5.12", "status": "fixed",
     "evidence_url": "https://example.invalid/docker", "checked": "2026-10-21"},
    {"cve": CVE, "vendor": "rhel", "stream": "9", "package": "php", "branch": "8.2",
     "match": "vercmp-rpm", "fixed": "8.2.35-1.module+el9.8.0+25111+a1450321", "status": "fixed",
     "evidence_url": "https://example.invalid/rhsa", "checked": "2026-10-21"},
]


def b(vendor, stream, package, version, scheme):
    return {"source": "test", "vendor": vendor, "stream": stream, "package": package,
            "branch": _branch(version), "version": version, "scheme": scheme, "where": "test"}


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
        self.check(b("docker-official", "8.5", "php", "8.5.12", "upstream"), "fixed")
        self.check(b("docker-official", "8.5", "php", "8.5.11", "upstream"), "not-fixed")

    def test_other_branch_never_matches(self):
        # RHEL ships 8.1/8.2/8.3 module streams all named "php". An 8.3 build
        # compares higher than the 8.2 fix, so it must not match that record.
        self.check(b("rhel", "9", "php", "8.2.35-1.module+el9.8.0+25111+a1450321", "vercmp-rpm"), "fixed")
        self.check(b("rhel", "9", "php", "8.2.30-1.module+el9.7.0+24000+a1450321", "vercmp-rpm"), "not-fixed")
        self.check(b("rhel", "9", "php", "8.3.15-1.module+el9.6.0+23000+bbbbbbbb", "vercmp-rpm"), "unknown")


class TestBundledData(unittest.TestCase):
    def test_every_record_valid(self):
        records = load_records()
        self.assertTrue(records)
        for r in records:
            with self.subTest(vendor=r["vendor"], stream=r["stream"], package=r["package"], cve=r["cve"]):
                self.assertEqual(validate_record(r), [])

    def test_validator_rejects_branchless_generic_package(self):
        bad = {"cve": CVE, "vendor": "rhel", "stream": "9", "package": "php", "match": "vercmp-rpm",
               "fixed": "8.2.35-1", "status": "fixed", "evidence_url": "https://x", "checked": "2026-10-22"}
        self.assertIn("package name doesn't pin the PHP branch; set 'branch'", validate_record(bad))

    def test_both_cves_present(self):
        cves = {r["cve"] for r in load_records()}
        self.assertEqual(cves, {"CVE-2026-109618", "CVE-2026-109619"})


class TestExitCode(unittest.TestCase):
    def report(self, builds, workers=()):
        inv = {"builds": builds, "workers": list(workers)}
        return resolve(inv, RECORDS, [CVE])

    def test_all_fixed(self):
        r = self.report([b("docker-official", "8.5", "php", "8.5.12", "upstream")])
        self.assertEqual(exit_code(r), 0)

    def test_not_fixed_wins_over_unknown(self):
        r = self.report([b("docker-official", "8.5", "php", "8.5.11", "upstream"),
                         b("cpanel", "*", "ea-php74", "7.4.33-12.el9", "vercmp-rpm")])
        self.assertEqual(exit_code(r), 1)

    def test_unknown(self):
        r = self.report([b("cpanel", "*", "ea-php74", "7.4.33-12.el9", "vercmp-rpm")])
        self.assertEqual(exit_code(r), 2)

    def test_stale_worker_fails_even_when_fixed(self):
        r = self.report([b("docker-official", "8.5", "php", "8.5.12", "upstream")],
                        workers=[{"pid": "1", "exe": "/usr/sbin/php-fpm (deleted)", "stale": True}])
        self.assertEqual(exit_code(r), 1)

    def test_no_php(self):
        self.assertEqual(exit_code(self.report([])), 0)


if __name__ == "__main__":
    unittest.main()
