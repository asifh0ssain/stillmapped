import json
import os
import tempfile
import unittest
from unittest.mock import patch

from phpfixed import collect as c


def fake_runner(outputs):
    """Runner stub: maps the command's first words (after docker's -H) to canned stdout."""
    def runner(cmd):
        words = [w for w in cmd if w not in c._DOCKER[1:]]
        return outputs.get(" ".join(words[:2]))
    return runner


def write(root, rel, text):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)
    return path


def dpkg_status(*pkgs):
    return "\n\n".join(f"Package: {n}\nStatus: {s}\nVersion: {v}\nDescription: x\n continued: line"
                       for n, v, s in pkgs) + "\n"


OK = "install ok installed"
DPKG = dpkg_status(
    ("php8.3-fpm", "8.3.6-0ubuntu0.24.04.12", OK),
    ("php8.3-cli", "8.3.6-0ubuntu0.24.04.12", OK),
    ("php8.3-mysql", "8.3.6-0ubuntu0.24.04.12", OK),      # extension: ignored
    ("libapache2-mod-php8.3", "8.3.6-0ubuntu0.24.04.12", OK),
    ("php8.5-fpm", "8.5.12-1+ubuntu24.04.1+deb.sury.org+1", OK),
    ("php8.1-fpm", "8.1.2-1ubuntu2.20", "deinstall ok config-files"),  # removed: ignored
    ("nginx", "1.24.0-2ubuntu7", OK),
)

RPM_OUT = "\n".join([
    "php-fpm\t(none):8.2.35-1.module+el9.8.0+25111+a1450321",
    "php-common\t(none):8.2.35-1.module+el9.8.0+25111+a1450321",
    "ea-php74-php-fpm\t(none):7.4.33-12.el9",
    "alt-php81-fpm\t(none):8.1.33-3.el9",
    "plesk-php82-fpm\t(none):8.2.35-1centos.9.261021.1200",
    "php82-php-fpm\t(none):8.2.35-1.el9.remi",
    "php-pecl-redis\t(none):6.0.2-1.el9",                # ignored
])


def root_with_dpkg(text):
    root = tempfile.mkdtemp()
    write(root, "var/lib/dpkg/status", text)
    return root


class TestOsRelease(unittest.TestCase):
    def _root(self, text):
        d = tempfile.mkdtemp()
        write(d, "etc/os-release", text)
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
        builds, problems = c.from_dpkg(("ubuntu", "24.04"), root_with_dpkg(DPKG))
        got = {(b["vendor"], b["stream"], b["package"], b["where"]) for b in builds}
        self.assertEqual(got, {
            ("ubuntu", "24.04", "php8.3", "php8.3-fpm"),
            ("ubuntu", "24.04", "php8.3", "php8.3-cli"),
            ("ubuntu", "24.04", "php8.3", "libapache2-mod-php8.3"),
            ("sury", "*", "php8.5", "php8.5-fpm"),
        })
        self.assertTrue(all(b["scheme"] == "vercmp-deb" for b in builds))
        self.assertEqual(problems, [])

    def test_held_and_half_states_count_as_installed(self):
        # Audit: only 'ii' used to count, so held (hi) packages were skipped.
        for status in ("hold ok installed", "reinstreq ok installed", "purge ok installed",
                       "install ok half-configured", "install ok unpacked"):
            with self.subTest(status=status):
                builds, _ = c.from_dpkg(("ubuntu", "24.04"), root_with_dpkg(
                    dpkg_status(("php8.3-fpm", "8.3.6-0ubuntu0.24.04.12", status))))
                self.assertEqual(len(builds), 1)

    def test_no_dpkg(self):
        self.assertEqual(c.from_dpkg(("debian", "12"), tempfile.mkdtemp()), ([], []))

    def test_unreadable_dpkg_is_a_problem(self):
        root = root_with_dpkg(DPKG)
        with patch("builtins.open", side_effect=PermissionError(13, "Permission denied")):
            builds, problems = c.from_dpkg(("debian", "12"), root)
        self.assertEqual(builds, [])
        self.assertEqual(problems, ["dpkg database unreadable: Permission denied"])


class TestRpm(unittest.TestCase):
    def setUp(self):
        patcher = patch.object(c, "_which", return_value="/usr/bin/rpm")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_parse(self):
        builds, _ = c.from_rpm(("almalinux", "9"), fake_runner({"rpm -qa": RPM_OUT}))
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
        builds, _ = c.from_rpm(("sles", "15.7"), fake_runner({"rpm -qa": out}))
        self.assertEqual({(b["package"], b["branch"]) for b in builds}, {("php8", "8.3"), ("php7", "7.4")})

    def test_failing_rpm_is_a_problem(self):
        # Audit: a failed package query used to look like "no PHP".
        builds, problems = c.from_rpm(("rhel", "9"), fake_runner({}))
        self.assertEqual(builds, [])
        self.assertEqual(len(problems), 1)

    def test_branch_ignores_epoch(self):
        self.assertEqual(c.branch("1:7.4.33-31+0~20261021"), "7.4")


class TestRun(unittest.TestCase):
    def test_fixed_path_and_minimal_env(self):
        with patch.object(c.shutil, "which", return_value="/usr/bin/rpm") as which, \
             patch.object(c.subprocess, "run") as run:
            run.return_value.returncode, run.return_value.stdout = 0, "out"
            self.assertEqual(c.run(["rpm", "-qa"]), "out")
        self.assertEqual(which.call_args.kwargs["path"], c._PATH)
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["/usr/bin/rpm", "-qa"])
        self.assertEqual(kwargs["env"], {"PATH": c._PATH, "LC_ALL": "C"})
        self.assertIs(kwargs["stdin"], c.subprocess.DEVNULL)

    def test_missing_command(self):
        with patch.object(c.shutil, "which", return_value=None):
            self.assertIsNone(c.run(["rpm", "-qa"]))


class TestDocker(unittest.TestCase):
    def setUp(self):
        patcher = patch.object(c, "_which", return_value="/usr/bin/docker")
        patcher.start()
        self.addCleanup(patcher.stop)

    def docker(self, *images):
        lines = "\n".join(f"{i}\t{json.dumps(tags)}\t{json.dumps(env)}" for i, tags, env in images)
        calls = []

        def runner(cmd):
            calls.append(cmd)
            if "ls" in cmd:
                return "\n".join(i for i, _, _ in images)
            return lines
        return c.from_docker(runner), calls

    def test_socket_pinned(self):
        _, calls = self.docker(("sha256:a", ["php:8.5"], ["PHP_VERSION=8.5.12"]))
        self.assertTrue(all(cmd[:3] == c._DOCKER for cmd in calls))

    def test_official_and_derived_images(self):
        # Audit: images built FROM php used to be skipped.
        (builds, problems), _ = self.docker(
            ("sha256:a", ["php:8.5-fpm"], ["PHP_VERSION=8.5.12"]),
            ("sha256:b", ["acme/app:1"], ["PATH=/x", "PHP_VERSION=8.5.11"]),
            ("sha256:c", ["nginx:1"], ["NGINX_VERSION=1.27"]))
        self.assertEqual({(b["where"], b["version"]) for b in builds},
                         {("php:8.5-fpm", "8.5.12"), ("acme/app:1", "8.5.11")})
        self.assertEqual(problems, [])

    def test_null_env_and_tags(self):
        # Audit: a 'null' Env crashed the whole run.
        (builds, problems), _ = self.docker(("sha256:a", None, None))
        self.assertEqual((builds, problems), ([], []))

    def test_daemon_down_is_a_problem(self):
        builds, problems = c.from_docker(lambda cmd: None)
        self.assertEqual(builds, [])
        self.assertEqual(len(problems), 1)

    def test_garbage_metadata_is_a_problem(self):
        builds, problems = c.from_docker(lambda cmd: "sha256:a" if "ls" in cmd else "not\ttsv")
        self.assertEqual(len(problems), 1)


class TestFilesystemSources(unittest.TestCase):
    def test_homebrew(self):
        root = tempfile.mkdtemp()
        for d in ("php/8.5.12_1", "php@8.2/8.2.34", "phpunit/8.5.12", "phpstan/2.1.0"):
            os.makedirs(os.path.join(root, "opt/homebrew/Cellar", d))
        builds, _ = c.from_homebrew(root)
        # Audit: phpunit 8.5.12 used to be read as PHP 8.5.12.
        self.assertEqual({(b["vendor"], b["branch"], b["version"]) for b in builds},
                         {("upstream", "8.5", "8.5.12"), ("upstream", "8.2", "8.2.34")})

    def test_directadmin_requires_marker(self):
        self.assertEqual(c.from_directadmin(tempfile.mkdtemp()), ([], []))

    def test_directadmin_reads_header_never_executes(self):
        root = tempfile.mkdtemp()
        os.makedirs(os.path.join(root, "usr/local/directadmin"))
        for prefix, version in (("php85", "8.5.12RC1"), ("php83", "8.3.36")):
            write(root, f"usr/local/{prefix}/bin/php", "#!/bin/sh\nexit 99\n")
            write(root, f"usr/local/{prefix}/include/php/main/php_version.h",
                  f'#define PHP_MAJOR_VERSION 8\n#define PHP_VERSION "{version}"\n')
        write(root, "usr/local/php74/bin/php", "")   # no header: can't tell
        with patch.object(c.subprocess, "run", side_effect=AssertionError("executed")):
            builds, problems = c.from_directadmin(root)
        # Audit: 8.5.12RC1 used to be cut down to 8.5.12.
        self.assertEqual({b["version"] for b in builds}, {"8.5.12RC1", "8.3.36"})
        self.assertEqual(len(problems), 1)
        self.assertIn("php74", problems[0])


def fake_proc(root, pid, exe=None, maps="", ns="mnt:[1]"):
    d = os.path.join(root, "proc", str(pid))
    os.makedirs(os.path.join(d, "ns"))
    if exe:
        os.symlink(exe, os.path.join(d, "exe"))
    os.symlink(ns, os.path.join(d, "ns", "mnt"))
    with open(os.path.join(d, "maps"), "w") as fh:
        fh.write(maps)
    return d


class TestWorkers(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        fake_proc(self.root, 1, "/usr/lib/systemd/systemd")

    def test_stale_worker(self):
        fake_proc(self.root, 101, "/usr/sbin/php-fpm8.3 (deleted)")
        fake_proc(self.root, 102, "/usr/sbin/php-fpm8.3")
        fake_proc(self.root, 103, "/usr/sbin/nginx")
        fake_proc(self.root, 2)                       # kernel thread: no exe
        procs, problems = c.running_workers(self.root)
        self.assertEqual({(p["pid"], p["stale"]) for p in procs}, {("101", True), ("102", False)})
        self.assertEqual(problems, [])

    def test_apache_mod_php(self):
        # Audit: Apache running mod_php used to be ignored, so a stale
        # libphp after an upgrade went unreported.
        mapped = "7f00-7f01 r-xp 00000000 08:01 1234   /usr/lib/apache2/modules/libphp8.3.so (deleted)\n"
        fake_proc(self.root, 200, "/usr/sbin/apache2", maps=mapped)
        fake_proc(self.root, 201, "/usr/sbin/apache2", maps="7f00-7f01 r-xp 0 08:01 1 /usr/lib/x.so\n")
        procs, _ = c.running_workers(self.root)
        self.assertEqual([(p["pid"], p["stale"]) for p in procs], [("200", True)])

    def test_unowned_worker_is_a_problem(self):
        # Audit: PHP running from outside any checked build exited 0.
        fake_proc(self.root, 42, "/usr/local/bin/php-fpm")
        _, problems = c.running_workers(self.root)
        self.assertEqual(len(problems), 1)
        self.assertIn("/usr/local/bin/php-fpm", problems[0])

    def test_container_worker_left_to_docker_check(self):
        fake_proc(self.root, 43, "/usr/local/sbin/php-fpm", ns="mnt:[2]")
        procs, problems = c.running_workers(self.root)
        self.assertEqual((len(procs), problems), (1, []))

    def test_unreadable_is_a_problem(self):
        # Audit: unreadable processes were only a printed note.
        fake_proc(self.root, 300, "/usr/sbin/php-fpm8.3")
        with patch.object(c.os, "readlink", side_effect=PermissionError):
            _, problems = c.running_workers(self.root)
        self.assertTrue(any("unreadable" in p for p in problems))

    def test_no_proc_is_a_problem(self):
        self.assertEqual(len(c.running_workers(tempfile.mkdtemp())[1]), 1)


class TestCollect(unittest.TestCase):
    def setUp(self):
        self.root = root_with_dpkg(DPKG)
        write(self.root, "etc/os-release", 'ID=ubuntu\nVERSION_ID="24.04"\n')
        fake_proc(self.root, 1, "/usr/lib/systemd/systemd")
        patcher = patch.object(c, "_which", return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_dedupes_binaries_of_same_build(self):
        inv = c.collect(self.root, fake_runner({}))
        self.assertEqual(len(inv["builds"]), 2)  # ubuntu php8.3 + sury php8.5
        self.assertEqual(inv["problems"], [])

    def test_running_php_with_no_build_is_a_problem(self):
        os.remove(os.path.join(self.root, "var/lib/dpkg/status"))
        fake_proc(self.root, 50, "/usr/sbin/php-fpm8.3")
        inv = c.collect(self.root, fake_runner({}))
        self.assertIn("PHP is running but no installed PHP build was found", inv["problems"])


if __name__ == "__main__":
    unittest.main()
