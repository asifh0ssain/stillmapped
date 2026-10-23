import contextlib
import io
import json
import unittest
from unittest.mock import patch

from phpfixed import cli

INV = {"os": {"id": "ubuntu", "stream": "24.04"}, "workers": [], "problems": [],
       "builds": [{"source": "dpkg", "vendor": "ubuntu", "stream": "24.04", "package": "php8.3",
                   "branch": "8.3", "version": "8.3.6-0ubuntu0.24.04.13", "scheme": "vercmp-deb",
                   "where": "php8.3-fpm\x1b]0;owned\x07"}]}


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


if __name__ == "__main__":
    unittest.main()
