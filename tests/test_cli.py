import contextlib
import io
import json
import unittest
from unittest.mock import patch

from phpfixed import cli

INV = {"os": {"id": "ubuntu", "stream": "24.04"}, "workers": [], "problems": [],
       "builds": [{"source": "dpkg", "vendor": "ubuntu", "stream": "24.04", "package": "php8.3",
                   "branch": "8.3", "version": "8.3.6-0ubuntu0.24.04.13", "scheme": "vercmp-deb",
                   "where": "php8.3-fpm\x1b]0;owned\x07", "module": "php", "db": "host"}]}


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
        code, out, _ = run("--cve", "CVE-2026-109618")
        self.assertEqual(code, 0)
        self.assertNotIn("\x1b", out)
        self.assertIn("\\x1b", out)

    def test_problems_shown_and_exit_2(self):
        code, out, _ = run(inv={**INV, "problems": ["no /proc: running PHP processes not checked"]})
        self.assertEqual(code, 2)
        self.assertIn("[NOT FULLY CHECKED]", out)

    def test_restart_receipt_scope_and_database_in_output(self):
        from phpfixed.resolve import load_records
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
        with patch.object(cli, "load_records", return_value=load_records() + [rec]):
            code, out, _ = run("--cve", "CVE-TEST-0002", inv=inv)
            jcode, jout, _ = run("--cve", "CVE-TEST-0002", "--json", inv=inv)
        self.assertEqual((code, jcode), (1, 1))
        self.assertIn("[RESTART-NEEDED] CVE-TEST-0002", out)
        self.assertIn("in-memory version unknown, restart needed", out)
        self.assertNotIn("NOT-FIXED", out)
        self.assertIn("pid:    469 maps /usr/lib/x86_64-linux-gnu/libcrypto.so.3 (deleted)", out)
        self.assertIn("container package database", out)
        self.assertIn("[SCOPE] libcrypto.so.3: dynamically linked copies only", out)
        j = json.loads(jout)
        self.assertTrue(j["limits"][0].startswith("libcrypto.so.3: dynamically linked copies only"))
        self.assertEqual([r["status"] for r in j["results"]], ["fixed", "restart-needed"])


if __name__ == "__main__":
    unittest.main()
