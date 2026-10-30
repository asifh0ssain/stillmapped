import unittest

from stillmapped.vercmp import compare, compare_deb, compare_rpm, rpmvercmp, split_evr


# Vectors from rpm's own test suite (tests/rpmvercmp.at).
RPM_VECTORS = [
    ("1.0", "1.0", 0), ("1.0", "2.0", -1), ("2.0", "1.0", 1),
    ("2.0.1", "2.0.1", 0), ("2.0", "2.0.1", -1), ("2.0.1", "2.0", 1),
    ("2.0.1a", "2.0.1a", 0), ("2.0.1a", "2.0.1", 1), ("2.0.1", "2.0.1a", -1),
    ("5.5p1", "5.5p1", 0), ("5.5p1", "5.5p2", -1), ("5.5p2", "5.5p1", 1),
    ("5.5p10", "5.5p10", 0), ("5.5p1", "5.5p10", -1), ("5.5p10", "5.5p1", 1),
    ("10xyz", "10.1xyz", -1), ("10.1xyz", "10xyz", 1),
    ("xyz10", "xyz10", 0), ("xyz10", "xyz10.1", -1), ("xyz10.1", "xyz10", 1),
    ("xyz.4", "xyz.4", 0), ("xyz.4", "8", -1), ("8", "xyz.4", 1),
    ("xyz.4", "2", -1), ("2", "xyz.4", 1),
    ("5.5p2", "5.6p1", -1), ("5.6p1", "5.5p2", 1),
    ("5.6p1", "6.5p1", -1), ("6.5p1", "5.6p1", 1),
    ("6.0.rc1", "6.0", 1), ("6.0", "6.0.rc1", -1),
    ("10b2", "10a1", 1), ("10a2", "10b2", -1),
    ("1.0aa", "1.0aa", 0), ("1.0a", "1.0aa", -1), ("1.0aa", "1.0a", 1),
    ("10.0001", "10.0001", 0), ("10.0001", "10.1", 0), ("10.1", "10.0001", 0),
    ("10.0001", "10.0039", -1), ("10.0039", "10.0001", 1),
    ("4.999.9", "5.0", -1), ("5.0", "4.999.9", 1),
    ("20101121", "20101121", 0), ("20101121", "20101122", -1), ("20101122", "20101121", 1),
    ("2_0", "2_0", 0), ("2.0", "2_0", 0), ("2_0", "2.0", 0),
    ("a", "a", 0), ("a+", "a+", 0), ("a+", "a_", 0), ("a_", "a+", 0),
    ("+a", "+a", 0), ("+a", "_a", 0), ("_a", "+a", 0),
    ("+_", "+_", 0), ("_+", "+_", 0), ("_+", "_+", 0), ("+", "_", 0), ("_", "+", 0),
    ("1.0~rc1", "1.0~rc1", 0), ("1.0~rc1", "1.0", -1), ("1.0", "1.0~rc1", 1),
    ("1.0~rc1", "1.0~rc2", -1), ("1.0~rc2", "1.0~rc1", 1),
    ("1.0~rc1~git123", "1.0~rc1~git123", 0), ("1.0~rc1~git123", "1.0~rc1", -1),
    ("1.0~rc1", "1.0~rc1~git123", 1),
    ("1.0^", "1.0^", 0), ("1.0^", "1.0", 1), ("1.0", "1.0^", -1),
    ("1.0^git1", "1.0^git1", 0), ("1.0^git1", "1.0", 1), ("1.0", "1.0^git1", -1),
    ("1.0^git1", "1.0^git2", -1), ("1.0^git2", "1.0^git1", 1),
    ("1.0^git1", "1.01", -1), ("1.01", "1.0^git1", 1),
    ("1.0^20160101", "1.0^20160101", 0), ("1.0^20160101", "1.0.1", -1),
    ("1.0.1", "1.0^20160101", 1),
    ("1.0^20160101^git1", "1.0^20160101^git1", 0),
    ("1.0^20160102", "1.0^20160101^git1", 1), ("1.0^20160101^git1", "1.0^20160102", -1),
    ("1.0~rc1^git1", "1.0~rc1^git1", 0), ("1.0~rc1^git1", "1.0~rc1", 1),
    ("1.0~rc1", "1.0~rc1^git1", -1),
    ("1.0^git1~pre", "1.0^git1~pre", 0), ("1.0^git1", "1.0^git1~pre", 1),
    ("1.0^git1~pre", "1.0^git1", -1),
]

# dpkg ordering rules (deb-version(7)).
DEB_VECTORS = [
    ("1.0", "1.0", 0), ("1.0", "2.0", -1), ("2.0", "1.0", 1),
    ("1:1.0", "2.0", 1), ("0:1.0", "1.0", 0),
    ("1.0-1", "1.0-2", -1), ("1.0", "1.0-0", 0),
    ("1.0~rc1", "1.0", -1), ("1.0~~", "1.0~", -1), ("1.0~", "1.0", -1),
    ("1.0", "1.0+", -1), ("1.0a", "1.0", 1), ("1.0a", "1.0+", -1),
    ("1.0-1", "1.0-1+b1", -1), ("1.0.10", "1.0.9", 1), ("1.0.010", "1.0.10", 0),
]

# Real PHP package strings of the shapes we will see on hosts.
DEB_REAL = [
    ("8.2.7-1~deb12u3", "8.2.35-1~deb12u1", -1),
    ("8.2.35-1~deb12u1", "8.2.35-1", -1),
    ("8.4.26-1", "8.4.27-1~deb13u1", -1),
    ("8.3.6-0ubuntu0.24.04.12", "8.3.6-0ubuntu0.24.04.13", -1),
    ("8.3.6-0ubuntu0.24.04.13", "8.3.6-0ubuntu0.24.04.13", 0),
    ("7.4.3-4ubuntu2.29+esm5", "7.4.3-4ubuntu2.29+esm4", 1),
    ("7.4.3-4ubuntu2.29", "7.4.3-4ubuntu2.29+esm5", -1),
    ("1:7.4.33-30+0~20260901.1+debian12~1.gbp1", "1:7.4.33-31+0~20261021.1+debian12~1.gbp1", -1),
    ("8.5.12-1+0~20261021.1+debian12~1.gbp1", "1:7.4.33-31", -1),  # epoch wins
]

RPM_REAL = [
    ("8.2.34-1.module+el9.8.0+24000+a1450321", "8.2.35-1.module+el9.8.0+25111+a1450321", -1),
    ("8.2.35-1.module+el9.8.0+25111+a1450321", "8.2.35-1.module+el9.8.0+25111+a1450321", 0),
    ("8.3.36-150700.3.24.1", "8.3.36-150700.3.23.2", 1),
    ("0:8.2.35-1.el9", "8.2.35-1.el9", 0),
    ("1:8.0.0-1.el9", "8.2.35-1.el9", 1),
]


class TestRpmVercmp(unittest.TestCase):
    def test_rpm_suite_vectors(self):
        for a, b, want in RPM_VECTORS:
            with self.subTest(a=a, b=b):
                self.assertEqual(rpmvercmp(a, b), want)

    def test_real_evr(self):
        for a, b, want in RPM_REAL:
            with self.subTest(a=a, b=b):
                self.assertEqual(compare_rpm(a, b), want)
                self.assertEqual(compare_rpm(b, a), -want)


class TestDebVercmp(unittest.TestCase):
    def test_rule_vectors(self):
        for a, b, want in DEB_VECTORS:
            with self.subTest(a=a, b=b):
                self.assertEqual(compare_deb(a, b), want)
                self.assertEqual(compare_deb(b, a), -want)

    def test_real_versions(self):
        for a, b, want in DEB_REAL:
            with self.subTest(a=a, b=b):
                self.assertEqual(compare_deb(a, b), want)
                self.assertEqual(compare_deb(b, a), -want)

    def test_split(self):
        self.assertEqual(split_evr("1:7.4.33-31+x"), (1, "7.4.33", "31+x"))
        self.assertEqual(split_evr("8.5.12"), (0, "8.5.12", ""))
        self.assertEqual(split_evr("1.2-3-4"), (0, "1.2-3", "4"))
        with self.assertRaises(ValueError):
            split_evr("x:1.0")


class TestDispatch(unittest.TestCase):
    def test_upstream(self):
        self.assertEqual(compare("upstream", "8.5.11", "8.5.12"), -1)
        self.assertEqual(compare("upstream", "8.5.12", "8.5.12"), 0)
        self.assertEqual(compare("upstream", "8.4.100", "8.4.27"), 1)

    def test_upstream_refuses_prerelease(self):
        for v in ("8.5.12RC1", "8.5.12-dev", "8.5.12junk", "8.5", " "):
            with self.subTest(v=v), self.assertRaises(ValueError):
                compare("upstream", v, "8.5.12")

    def test_unknown_scheme(self):
        with self.assertRaises(ValueError):
            compare("nope", "1", "2")


if __name__ == "__main__":
    unittest.main()
