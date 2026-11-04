import contextlib
import io
import json
import pathlib
import re
import unittest
from unittest.mock import patch

from stillmapped import __version__, cli

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


class TestRestartReceipt(unittest.TestCase):
    """Owner 2026-11-04 (php2shell report): each PHP process on old code is listed with its
    PID, name and binary, and advice by process type, in the text receipt."""

    def receipt(self, *workers):
        ws = [{"pid": pid, "name": name, "exe": exe, "stale": True, "mapped_sha256": "aa", "installed_sha256": "bb"}
              for pid, name, exe in workers]
        code, out, _ = run("--cve", "CVE-2026-109618", inv={**INV, "workers": ws})
        self.assertEqual(code, 1)
        self.assertNotIn("worker", out)
        return [line for line in out.splitlines() if line.startswith(("[RESTART NEEDED]", "  - pid"))]

    def test_php_fpm_master_and_pool_restart_php_fpm(self):
        self.assertEqual(self.receipt(("6825", "php-fpm8.2", "/usr/sbin/php-fpm8.2 (deleted)"),
                                      ("6826", "php-fpm8.2", "/usr/sbin/php-fpm8.2 (deleted)"),
                                      ("7001", "php-fpm", "/opt/cpanel/ea-php82/root/usr/sbin/php-fpm (deleted)")), [
            "[RESTART NEEDED] 3 PHP process(es) still run a deleted (pre-upgrade) binary:",
            "  - pid 6825 php-fpm8.2, /usr/sbin/php-fpm8.2 (deleted): restart php-fpm",
            "  - pid 6826 php-fpm8.2, /usr/sbin/php-fpm8.2 (deleted): restart php-fpm",
            "  - pid 7001 php-fpm, /opt/cpanel/ea-php82/root/usr/sbin/php-fpm (deleted): restart php-fpm"])

    def test_server_with_libphp_restarts_the_web_server(self):
        self.assertEqual(self.receipt(("200", "apache2", "/usr/lib/apache2/modules/libphp8.2.so (deleted)"),
                                      ("300", "httpd-prefork", "/usr/lib64/apache2/mod_php8.so (deleted)"),
                                      ("71", "uwsgi-core", "/usr/lib/apache2/modules/libphp8.3.so (deleted)"))[1:], [
            "  - pid 200 apache2, /usr/lib/apache2/modules/libphp8.2.so (deleted): restart the web server",
            "  - pid 300 httpd-prefork, /usr/lib64/apache2/mod_php8.so (deleted): restart the web server",
            "  - pid 71 uwsgi-core, /usr/lib/apache2/modules/libphp8.3.so (deleted): restart the web server"])

    def test_cli_queue_worker_or_daemon_restarts_the_process(self):
        self.assertEqual(self.receipt(("6828", "php", "/usr/bin/php8.2 (deleted)"),
                                      ("401", "php-cgi8.2", "/usr/bin/php-cgi8.2 (deleted)"),
                                      ("402", "php", "/usr/bin/php8.2"))[1:], [
            "  - pid 6828 php, /usr/bin/php8.2 (deleted): restart this process (or the supervisor that runs it)",
            "  - pid 401 php-cgi8.2, /usr/bin/php-cgi8.2 (deleted): restart this process (or the supervisor that runs it)",
            "  - pid 402 php, /usr/bin/php8.2: restart this process (or the supervisor that runs it)"])

    def test_advice_follows_the_mapped_file_not_the_name(self):
        # The name is the process's own choice (prctl, exec under another name); the mapped path is the kernel's.
        lines = self.receipt(("9", "php-fpm8.2", "/usr/bin/php8.2 (deleted)"), ("10", "\x1b]0;x\x07", "/usr/sbin/php-fpm8.2 (deleted)"))
        self.assertEqual(lines[1:], ["  - pid 9 php-fpm8.2, /usr/bin/php8.2 (deleted): restart this process (or the supervisor that runs it)",
                                     "  - pid 10 '\\x1b]0;x\\x07', /usr/sbin/php-fpm8.2 (deleted): restart php-fpm"])


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


class TestStrict(unittest.TestCase):
    """Codex Security finding 2: the default run's exit 0 ignores CVEs it did not judge."""

    def records(self, judged_only=False):
        other = {**OSSL_REC, "cve": "CVE-TEST-0003", "vendor": "ubuntu", "stream": "24.04", "package": "libssl3t64",
                 "fixed": "3.0.13-0ubuntu3.5", "origin": r"^3\.0\.13-0ubuntu3\.\d+$"}
        return [OSSL_REC] + ([] if judged_only else [other])

    def test_default_run_exit_0_with_a_not_judged_cve(self):
        with patch.object(cli, "load_records", return_value=self.records()):
            code, out, _ = run("--json", inv=NO_PHP)
        report = json.loads(out)
        self.assertEqual((code, report["not_judged"], report["problems"]), (0, {"debian 12": ["CVE-TEST-0003"]}, []))

    def test_strict_makes_a_not_judged_cve_exit_2(self):
        with patch.object(cli, "load_records", return_value=self.records()):
            code, out, _ = run("--strict", inv=NO_PHP)
        self.assertEqual(code, 2)
        self.assertIn("--strict: 1 CVEs have no vendor record for a build found here and were not judged", out)

    def test_strict_exit_0_when_every_cve_is_judged(self):
        with patch.object(cli, "load_records", return_value=self.records(judged_only=True)):
            code, _, _ = run("--strict", inv=NO_PHP)
        self.assertEqual(code, 0)

    def test_trust_in_text_receipt_and_json(self):
        # Codex Security finding 1: every result names the evidence it rests on.
        with patch.object(cli, "load_records", return_value=self.records(judged_only=True)):
            _, out, _ = run("--all", inv=NO_PHP)
            _, js, _ = run("--json", inv=NO_PHP)
        self.assertIn("  trust:  host-pkgdb\n", out)
        self.assertEqual({r["trust"] for r in json.loads(js)["results"]}, {"host-pkgdb"})


class TestRunDir(unittest.TestCase):
    def test_fixture_directories_go_under_one_per_run_directory(self):
        import tempfile
        import tests
        self.assertEqual(tempfile.gettempdir(), tests.RUN_DIR)
        self.assertTrue(tempfile.mkdtemp().startswith(tests.RUN_DIR + "/"))


class TestVersion(unittest.TestCase):
    def test_pyproject_version_equals_package_version(self):
        toml = (pathlib.Path(__file__).resolve().parent.parent / "pyproject.toml").read_text()
        self.assertEqual(re.search(r'^version = "([^"]+)"', toml, re.M).group(1), __version__)


if __name__ == "__main__":
    unittest.main()
