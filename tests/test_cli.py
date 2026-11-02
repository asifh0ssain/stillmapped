import contextlib
import io
import json
import unittest
from unittest.mock import patch

from stillmapped import cli

INV = {"os": {"id": "ubuntu", "stream": "24.04"}, "workers": [], "problems": [],
       "builds": [{"source": "dpkg", "vendor": "ubuntu", "stream": "24.04", "package": "php8.3",
                   "branch": "8.3", "version": "8.3.6-0ubuntu0.24.04.13", "scheme": "vercmp-deb",
                   "where": "php8.3-fpm\x1b]0;owned\x07", "module": "php", "db": "host"}]}


# The PHP CVEs these tests were written against; the rest of the bundled data is left out.
HAND_CVES = ["CVE-2026-109618", "CVE-2026-109619"]


def run(*argv, inv=INV):
    out, err = io.StringIO(), io.StringIO()
    with patch.object(cli, "collect", return_value=inv), \
         contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TestCli(unittest.TestCase):
    def test_unknown_cve_is_an_error(self):
        # Audit: an id with no bundled data used to exit 0 with no results.
        code, out, err = run("--cve", "CVE-NOT-REAL")
        self.assertEqual((code, out), (3, ""))
        self.assertIn("no bundled data for CVE-NOT-REAL", err)

    def test_fixed_build(self):
        code, out, _ = run("--cve", "CVE-2026-109618", "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["results"][0]["status"], "fixed")

    def test_table_escapes_control_characters(self):
        code, out, _ = run("--cve", "CVE-2026-109618", "--all")
        self.assertEqual(code, 0)
        self.assertNotIn("\x1b", out)
        self.assertIn("\\x1b", out)

    def test_problems_shown_and_exit_2(self):
        code, out, _ = run(inv={**INV, "problems": ["no /proc: running PHP processes not checked"]})
        self.assertEqual(code, 2)
        self.assertIn("[NOT FULLY CHECKED]", out)

    def test_restart_receipt_scope_and_database_in_output(self):
        from stillmapped.resolve import load_records
        rec = {"cve": "CVE-TEST-0002", "module": "openssl", "vendor": "debian", "stream": "12",
               "package": "libssl3", "branch": "3.0", "file": "libcrypto.so.3", "match": "vercmp-deb",
               "fixed": "3.0.14-1~deb12u2", "status": "fixed", "origin": r"^3\.0\.\d+-\d+~deb12u\d+$",
               "evidence_url": "https://example.invalid/dsa", "checked": "2026-10-29"}
        lib = {"source": "dpkg", "vendor": "debian", "stream": "12", "package": "libssl3", "branch": "3.0",
               "version": "3.0.14-1~deb12u2", "scheme": "vercmp-deb", "where": "libssl3",
               "module": "openssl", "db": "container"}
        m = {"pid": "469", "start": "4242", "path": "/usr/lib/x86_64-linux-gnu/libcrypto.so.3 (deleted)",
             "file": "libcrypto.so.3", "dev": "00:3f", "inode": "14821", "same": False, "build": lib,
             "mapped_sha256": "2744", "installed_sha256": "cf0a"}
        inv = {"os": {"id": "debian", "stream": "12"}, "builds": [lib], "workers": [], "mappings": [m], "problems": []}
        with patch.object(cli, "load_records", return_value=load_records(HAND_CVES) + [rec]):
            code, out, _ = run("--cve", "CVE-TEST-0002", inv=inv)
            jcode, jout, _ = run("--cve", "CVE-TEST-0002", "--json", inv=inv)
        self.assertEqual((code, jcode), (1, 1))
        self.assertIn("[RESTART-NEEDED] CVE-TEST-0002", out)
        self.assertIn("in-memory version unknown, restart needed", out)
        self.assertNotIn("NOT-FIXED", out)
        self.assertIn("pid:    469 maps /usr/lib/x86_64-linux-gnu/libcrypto.so.3 (deleted)", out)
        self.assertIn("container package database", out)
        self.assertIn("[SCOPE] libcrypto.so.3: every mapped libcrypto*.so* file is checked", out)
        j = json.loads(jout)
        self.assertIn("linked statically into a program is not seen", j["limits"][0])
        self.assertEqual([r["status"] for r in j["results"]], ["fixed", "restart-needed"])


OSSL_REC = {"cve": "CVE-TEST-0002", "module": "openssl", "vendor": "debian", "stream": "12",
            "package": "libssl3", "branch": "3.0", "file": "libcrypto.so.3", "match": "vercmp-deb",
            "fixed": "3.0.14-1~deb12u2", "status": "fixed", "origin": r"^3\.0\.\d+-\d+~deb12u\d+$",
            "evidence_url": "https://example.invalid/dsa", "checked": "2026-10-29"}
NO_PHP = {"os": {"id": "debian", "stream": "12"}, "workers": [], "mappings": [], "problems": [],
          "builds": [{"source": "dpkg", "vendor": "debian", "stream": "12", "package": "libssl3",
                      "branch": "3.0", "version": "3.0.14-1~deb12u2", "scheme": "vercmp-deb",
                      "where": "libssl3", "module": "openssl", "db": "host"}]}


class TestReleasePush(unittest.TestCase):
    def run_no_php(self, *argv):
        from stillmapped.resolve import load_records
        with patch.object(cli, "load_records", return_value=load_records(HAND_CVES) + [OSSL_REC]):
            return run(*argv, inv=NO_PHP)

    def test_default_run_missing_module_is_info_and_exit_0(self):
        # Release push #1: a host without PHP reaches exit 0 for OpenSSL CVEs.
        code, out, _ = self.run_no_php()
        jcode, jout, _ = self.run_no_php("--json")
        self.assertEqual((code, jcode), (0, 0))
        self.assertIn("[INFO] no PHP build found", out)
        self.assertNotIn("[NOT FULLY CHECKED]", out)
        self.assertEqual((json.loads(jout)["problems"], json.loads(jout)["info"]),
                         ([], ["no PHP build found"]))

    def test_missing_php_states_what_is_not_seen(self):
        # Review 5 F1, F2 (owner's option b): exit 0 without PHP says what the scan cannot see.
        code, out, _ = self.run_no_php()
        jcode, jout, _ = self.run_no_php("--json")
        self.assertEqual((code, jcode), (0, 0))
        self.assertIn("[SCOPE] PHP that no package owns is seen only while running as php, php-fpm, php-cgi, lsphp or frankenphp, or with libphp loaded.", out)
        self.assertIn("PHP that no package owns is seen only while running as php, php-fpm, php-cgi, lsphp or frankenphp, or with libphp loaded.", json.loads(jout)["limits"])
        self.assertNotIn("not present", out)
        # Review 6 F2: present with a PHP build, absent when only non-PHP CVEs are named.
        self.assertIn("PHP that no package owns is seen only while running as php, php-fpm, php-cgi, lsphp or frankenphp, or with libphp loaded.", json.loads(run("--json")[1])["limits"])
        only_ossl = json.loads(self.run_no_php("--cve", "CVE-TEST-0002", "--json")[1])["limits"]
        self.assertNotIn("PHP that no package owns is seen only while running as php, php-fpm, php-cgi, lsphp or frankenphp, or with libphp loaded.", only_ossl)

    def test_cve_for_missing_module_stays_a_problem(self):
        # Release push #1: --cve for a module with no build is still exit 2.
        code, out, _ = self.run_no_php("--cve", "CVE-2026-109618")
        self.assertEqual(code, 2)
        self.assertIn("no PHP build found", out)

    def test_default_run_with_no_module_found_is_still_a_problem(self):
        # Fail closed: nothing found at all (e.g. an unsupported package manager) is never exit 0.
        code, out, _ = run(inv={**NO_PHP, "builds": []})
        self.assertEqual(code, 2)
        self.assertIn("no PHP build found", out)

    def test_container_build_does_not_make_a_module_present(self):
        # Review 5 F3: only a container's libssl3 made the host's empty check pass with exit 0.
        from stillmapped.resolve import load_records
        inv = {**NO_PHP, "builds": [{**NO_PHP["builds"][0], "db": "container"}]}
        with patch.object(cli, "load_records", return_value=load_records(HAND_CVES) + [OSSL_REC]):
            code, out, _ = run(inv=inv)
        self.assertEqual(code, 2)
        self.assertIn("no PHP build found", out)
        self.assertNotIn("[INFO]", out)

    def test_cve_flags_make_every_named_module_required(self):
        # Review 5 F6: an OpenSSL CVE named next to a PHP CVE must not lift the PHP requirement.
        code, out, _ = self.run_no_php("--cve", "CVE-2026-109618", "--cve", "CVE-TEST-0002")
        self.assertEqual(code, 2)
        self.assertIn("no PHP build found", out)

    def test_default_output_shows_not_fixed_and_unknown(self):
        # Review 5 F6: only fixed rows are hidden.
        from stillmapped.resolve import load_records
        old = {**NO_PHP["builds"][0], "version": "3.0.14-1~deb12u1"}
        odd = {**NO_PHP["builds"][0], "version": "3.0.15-1+thirdparty1"}
        with patch.object(cli, "load_records", return_value=load_records(HAND_CVES) + [OSSL_REC]):
            code, out, _ = run(inv={**NO_PHP, "builds": [old, odd]})
        self.assertEqual(code, 1)
        self.assertIn("[NOT-FIXED] CVE-TEST-0002  debian/libssl3 3.0.14-1~deb12u1", out)
        self.assertIn("[UNKNOWN] CVE-TEST-0002  debian/libssl3 3.0.15-1+thirdparty1", out)
        self.assertIn("\n0 fixed\n", out)

    def test_default_output_hides_fixed_and_counts_them(self):
        # Release push #2: fixed rows are a count; --all lists them; JSON keeps them.
        code, out, _ = self.run_no_php()
        _, all_out, _ = self.run_no_php("--all")
        _, jout, _ = self.run_no_php("--json")
        self.assertNotIn("[FIXED]", out)
        self.assertIn("\n1 fixed\n", out)
        self.assertIn("[FIXED] CVE-TEST-0002  debian/libssl3", all_out)
        self.assertEqual([r["status"] for r in json.loads(jout)["results"]], ["fixed"])

    def test_not_affected_shown_as_not_affected_and_counted(self):
        # Owner, 2026-11-02: "not-affected" counts like fixed and is shown as "not affected".
        from stillmapped.resolve import load_records
        na = {**OSSL_REC, "status": "not-affected"}
        del na["match"], na["fixed"]
        with patch.object(cli, "load_records", return_value=load_records(HAND_CVES) + [na]):
            code, out, _ = run("--cve", "CVE-TEST-0002", inv=NO_PHP)
            _, all_out, _ = run("--cve", "CVE-TEST-0002", "--all", inv=NO_PHP)
        self.assertEqual(code, 0)
        self.assertNotIn("[NOT AFFECTED]", out)
        self.assertIn("\n0 fixed\n1 not affected\n", out)
        self.assertIn("[NOT AFFECTED] CVE-TEST-0002  debian/libssl3", all_out)


if __name__ == "__main__":
    unittest.main()
