import os
import tempfile
import unittest

from phpfixed import collect as c


def fake_runner(outputs):
    """Runner stub: maps the command's first two words to canned stdout."""
    def runner(cmd):
        return outputs.get(" ".join(cmd[:2]))
    return runner


DPKG_OUT = "\n".join([
    "php8.3-fpm\t8.3.6-0ubuntu0.24.04.12\tii ",
    "php8.3-cli\t8.3.6-0ubuntu0.24.04.12\tii ",
    "php8.3-mysql\t8.3.6-0ubuntu0.24.04.12\tii ",      # extension: ignored
    "libapache2-mod-php8.3\t8.3.6-0ubuntu0.24.04.12\tii ",
    "php8.5-fpm\t8.5.12-1+ubuntu24.04.1+deb.sury.org+1\tii ",
    "php8.1-fpm\t8.1.2-1ubuntu2.20\trc ",               # removed: ignored
    "nginx\t1.24.0-2ubuntu7\tii ",
])

RPM_OUT = "\n".join([
    "php-fpm\t(none):8.2.35-1.module+el9.8.0+25111+a1450321",
    "php-common\t(none):8.2.35-1.module+el9.8.0+25111+a1450321",
    "ea-php74-php-fpm\t(none):7.4.33-12.el9",
    "alt-php81-fpm\t(none):8.1.33-3.el9",
    "plesk-php82-fpm\t(none):8.2.35-1centos.9.261021.1200",
    "php82-php-fpm\t(none):8.2.35-1.el9.remi",
    "php-pecl-redis\t(none):6.0.2-1.el9",                # ignored
])


class TestOsRelease(unittest.TestCase):
    def _root(self, text):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "etc"))
        with open(os.path.join(d, "etc/os-release"), "w") as fh:
            fh.write(text)
        return d

    def test_ubuntu_keeps_minor(self):
        self.assertEqual(c.os_release(self._root('ID=ubuntu\nVERSION_ID="24.04"\n')), ("ubuntu", "24.04"))

    def test_rhel_major_only(self):
        self.assertEqual(c.os_release(self._root('ID="almalinux"\nVERSION_ID="9.6"\n')), ("almalinux", "9"))

    def test_suse_keeps_service_pack(self):
        self.assertEqual(c.os_release(self._root('ID="sles"\nVERSION_ID="15.7"\n')), ("sles", "15.7"))

    def test_missing(self):
        self.assertEqual(c.os_release(tempfile.mkdtemp()), ("", ""))


class TestDpkg(unittest.TestCase):
    def test_parse(self):
        builds = c.from_dpkg(("ubuntu", "24.04"), fake_runner({"dpkg-query -W": DPKG_OUT}))
        got = {(b["vendor"], b["stream"], b["package"], b["where"]) for b in builds}
        self.assertEqual(got, {
            ("ubuntu", "24.04", "php8.3", "php8.3-fpm"),
            ("ubuntu", "24.04", "php8.3", "php8.3-cli"),
            ("ubuntu", "24.04", "php8.3", "libapache2-mod-php8.3"),
            ("sury", "*", "php8.5", "php8.5-fpm"),
        })
        self.assertTrue(all(b["scheme"] == "vercmp-deb" for b in builds))

    def test_no_dpkg(self):
        self.assertEqual(c.from_dpkg(("debian", "12"), fake_runner({})), [])


class TestRpm(unittest.TestCase):
    def test_parse(self):
        builds = c.from_rpm(("almalinux", "9"), fake_runner({"rpm -qa": RPM_OUT}))
        got = {(b["vendor"], b["package"], b["version"]) for b in builds}
        self.assertEqual(got, {
            ("almalinux", "php", "8.2.35-1.module+el9.8.0+25111+a1450321"),
            ("cpanel", "ea-php74", "7.4.33-12.el9"),
            ("cloudlinux", "alt-php81", "8.1.33-3.el9"),
            ("plesk", "plesk-php82", "8.2.35-1centos.9.261021.1200"),
            ("remi", "php82", "8.2.35-1.el9.remi"),
        })
        self.assertTrue(all(b["branch"] for b in builds))

    def test_suse_php8(self):
        out = "php8-fpm\t(none):8.3.36-150700.3.24.1\nphp7\t(none):7.4.33-150400.4.81.1"
        builds = c.from_rpm(("sles", "15.7"), fake_runner({"rpm -qa": out}))
        got = {(b["package"], b["branch"]) for b in builds}
        self.assertEqual(got, {("php8", "8.3"), ("php7", "7.4")})

    def test_branch_ignores_epoch(self):
        self.assertEqual(c.branch("1:7.4.33-31+0~20261021"), "7.4")


class TestFilesystemSources(unittest.TestCase):
    def test_homebrew(self):
        root = tempfile.mkdtemp()
        os.makedirs(os.path.join(root, "opt/homebrew/Cellar/php/8.5.12_1"))
        os.makedirs(os.path.join(root, "opt/homebrew/Cellar/php@8.2/8.2.34"))
        got = {(b["vendor"], b["branch"], b["version"]) for b in c.from_homebrew(root)}
        self.assertEqual(got, {("upstream", "8.5", "8.5.12"), ("upstream", "8.2", "8.2.34")})

    def test_directadmin_requires_marker(self):
        self.assertEqual(c.from_directadmin(tempfile.mkdtemp(), fake_runner({})), [])

    def test_stale_worker(self):
        root = tempfile.mkdtemp()
        for pid, target in (("101", "/usr/sbin/php-fpm8.3 (deleted)"),
                            ("102", "/usr/sbin/php-fpm8.3"),
                            ("103", "/usr/sbin/nginx")):
            os.makedirs(os.path.join(root, "proc", pid))
            os.symlink(target, os.path.join(root, "proc", pid, "exe"))
        procs, unreadable = c.running_workers(root)
        self.assertEqual(unreadable, 0)
        self.assertEqual({(p["pid"], p["stale"]) for p in procs}, {("101", True), ("102", False)})


class TestCollect(unittest.TestCase):
    def test_dedupes_binaries_of_same_build(self):
        root = tempfile.mkdtemp()
        os.makedirs(os.path.join(root, "etc"))
        with open(os.path.join(root, "etc/os-release"), "w") as fh:
            fh.write('ID=ubuntu\nVERSION_ID="24.04"\n')
        inv = c.collect(root, fake_runner({"dpkg-query -W": DPKG_OUT}))
        self.assertEqual(len(inv["builds"]), 2)  # ubuntu php8.3 + sury php8.5


if __name__ == "__main__":
    unittest.main()
