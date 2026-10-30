import os
import subprocess
import tempfile
import unittest
import zipfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestZipapp(unittest.TestCase):
    def test_single_file_build_keeps_exit_codes_data_and_hash(self):
        # Release push #3: one file to copy to /usr/local/bin; zipapp -m would turn every exit code into 0.
        with tempfile.TemporaryDirectory() as d:
            out = subprocess.run([os.path.join(REPO, "ci", "zipapp.sh"), d], capture_output=True, text=True, check=True)
            app = os.path.join(d, "stillmapped")
            with open(os.path.join(d, "stillmapped.sha256")) as fh:
                self.assertEqual(fh.read(), out.stdout)
            subprocess.run(["sha256sum", "-c", "--quiet", "stillmapped.sha256"], cwd=d, check=True)
            with open(app, "rb") as fh:
                self.assertEqual(fh.readline(), b"#!/usr/bin/python3\n")
            names = zipfile.ZipFile(app).namelist()
            self.assertIn("stillmapped/data/php2shell.json", names)
            self.assertFalse([n for n in names if "__pycache__" in n or n.endswith(".pyc")])
            # Review 5 F5: the same tree gives the same bytes, so anyone can rebuild and compare.
            again = subprocess.run([os.path.join(REPO, "ci", "zipapp.sh"), os.path.join(d, "again")],
                                   capture_output=True, text=True, check=True)
            self.assertEqual(again.stdout, out.stdout)
            bad = subprocess.run([app, "--cve", "CVE-NOT-REAL"], capture_output=True, text=True)
            self.assertEqual((bad.returncode, bad.stderr), (3, "stillmapped: no bundled data for CVE-NOT-REAL\n"))
            # Records load from inside the zip (an unknown CVE alone does not prove that).
            n = subprocess.run(["python3", "-c", "import sys; sys.path.insert(0, sys.argv[1]); "
                                "from stillmapped.resolve import load_records; print(len(load_records()))", app],
                               capture_output=True, text=True, check=True, cwd=d)
            self.assertGreater(int(n.stdout), 0)


if __name__ == "__main__":
    unittest.main()
