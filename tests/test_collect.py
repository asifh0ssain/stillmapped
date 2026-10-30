import hashlib
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from phpfixed import collect as c


def fake_runner(outputs):
    """Runner stub: maps the command's first words (after docker's -H) to canned stdout."""
    def runner(cmd, ok=(0,)):
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
# rpm -q --qf '[%{NAME}\t%{FILENAMES}\n]': php-common installs no PHP binary.
RPM_FILES = "\n".join([
    "php-fpm\t/usr/sbin/php-fpm",
    "php-common\t/usr/lib64/php/modules/json.so",
    "ea-php74-php-fpm\t/opt/cpanel/ea-php74/root/usr/sbin/php-fpm",
    "alt-php81-fpm\t/opt/alt/php81/usr/sbin/php-fpm",
    "plesk-php82-fpm\t/opt/plesk/php/8.2/sbin/php-fpm",
    "php82-php-fpm\t/opt/remi/php82/root/usr/sbin/php-fpm",
    "php8-fpm\t/usr/sbin/php-fpm",
    "php7\t/usr/bin/php",
    "apache2-mod_php8\t/usr/lib64/apache2/mod_php8.so",
])


# One file per package, as dpkg lists it. Only packages that install PHP
# itself (a binary or module) count as a PHP build.
DEB_LISTS = {
    "php8.3-fpm": "/.\n/usr/sbin\n/usr/sbin/php-fpm8.3\n",
    "php8.3-cli": "/usr/bin/php8.3",  # no trailing newline
    "php8.3-mysql": "/usr/lib/php/20230831/mysqli.so\n",
    "libapache2-mod-php8.3:amd64": "/usr/lib/apache2/modules/libphp8.3.so\n",
    "php8.5-fpm": "/usr/sbin/php-fpm8.5\n",
    "php8.1-fpm": "/usr/sbin/php-fpm8.1\n",
    "php8.2-fpm": "/usr/sbin/php-fpm8.2\n",
}


INSTALLED = b"installed code"  # what fake_proc puts in a packaged file it creates


def md5sums(files):
    return "".join(f"{hashlib.md5(INSTALLED).hexdigest()}  {f.lstrip('/')}\n" for f in files.split())


def root_with_dpkg(text):
    root = tempfile.mkdtemp()
    write(root, "var/lib/dpkg/status", text)
    for pkg, files in DEB_LISTS.items():
        write(root, f"var/lib/dpkg/info/{pkg}.list", files)
        write(root, f"var/lib/dpkg/info/{pkg}.md5sums", md5sums(files))
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
                       "install ok half-configured", "install ok unpacked", "install ok half-installed"):
            with self.subTest(status=status):
                builds, _ = c.from_dpkg(("ubuntu", "24.04"), root_with_dpkg(
                    dpkg_status(("php8.3-fpm", "8.3.6-0ubuntu0.24.04.12", status))))
                self.assertEqual(len(builds), 1)

    def state(self, status, problem):
        """Rule: 'install ok installed' and 'hold ok installed' pass; any other
        state keeps the build and is a problem. PHP and library packages alike."""
        for pkg in ("php8.3-fpm", "libssl3"):
            with self.subTest(pkg=pkg):
                root = root_with_dpkg(dpkg_status((pkg, "8.3.6-0ubuntu0.24.04.12", status)))
                builds, problems = c.from_dpkg(("ubuntu", "24.04"), root, {"libssl3": "openssl"})
                self.assertEqual((len(builds), bool(problems)), (1, problem))

    def test_state_install_ok_installed_passes(self):
        self.state("install ok installed", False)

    def test_state_hold_ok_installed_passes(self):
        self.state("hold ok installed", False)

    def test_state_half_installed_is_a_problem(self):
        self.state("install ok half-installed", True)

    def test_state_unpacked_is_a_problem(self):
        self.state("install ok unpacked", True)

    def test_state_half_configured_is_a_problem(self):
        self.state("install ok half-configured", True)

    def test_state_triggers_awaited_is_a_problem(self):
        self.state("install ok triggers-awaited", True)

    def test_state_triggers_pending_is_a_problem(self):
        self.state("install ok triggers-pending", True)

    def test_state_reinstreq_is_a_problem(self):
        self.state("install reinstreq installed", True)

    def test_state_deinstall_wanted_is_a_problem(self):
        self.state("deinstall ok installed", True)

    def test_state_hold_half_configured_is_a_problem(self):
        self.state("hold ok half-configured", True)

    def test_package_without_php_file_is_not_a_build(self):
        # Open risk 2: only a package that installs PHP itself counts.
        root = root_with_dpkg(dpkg_status(("php8.3-common", "8.3.6-0ubuntu0.24.04.12", OK),
                                          ("php8.3-mysql", "8.3.6-0ubuntu0.24.04.12", OK)))
        write(root, "var/lib/dpkg/info/php8.3-common.list", "/usr/lib/php\n/usr/share/php8.3-common\n")
        self.assertEqual(c.from_dpkg(("ubuntu", "24.04"), root), ([], []))

    def test_php_package_without_file_list_is_a_problem(self):
        # Review #3: a missing .list silently dropped an unfixed php8.3-cli (exit 0).
        root = root_with_dpkg(dpkg_status(("php8.3-cli", "8.3.6-0ubuntu0.24.04.12", OK)))
        os.remove(os.path.join(root, "var/lib/dpkg/info/php8.3-cli.list"))
        builds, problems = c.from_dpkg(("ubuntu", "24.04"), root)
        self.assertEqual((builds, problems), ([], ["dpkg has no readable file list for php8.3-cli; it was not checked"]))

    def test_no_dpkg(self):
        self.assertEqual(c.from_dpkg(("debian", "12"), tempfile.mkdtemp()), ([], []))

    def test_unreadable_dpkg_is_a_problem(self):
        root = root_with_dpkg(DPKG)
        with patch.object(c, "_slurp", side_effect=PermissionError(13, "Permission denied")):
            builds, problems = c.from_dpkg(("debian", "12"), root)
        self.assertEqual(builds, [])
        self.assertEqual(problems, ["dpkg database unreadable: Permission denied"])


class TestRpm(unittest.TestCase):
    def setUp(self):
        patcher = patch.object(c, "_which", return_value="/usr/bin/rpm")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_parse(self):
        builds, _ = c.from_rpm(("almalinux", "9"), fake_runner({"rpm -qa": RPM_OUT, "rpm -q": RPM_FILES}))
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
        builds, _ = c.from_rpm(("sles", "15.7"), fake_runner({"rpm -qa": out, "rpm -q": RPM_FILES}))
        self.assertEqual({(b["package"], b["branch"]) for b in builds}, {("php8", "8.3"), ("php7", "7.4")})

    def test_failing_rpm_is_a_problem(self):
        # Audit: a failed package query used to look like "no PHP".
        builds, problems = c.from_rpm(("rhel", "9"), fake_runner({}))
        self.assertEqual(builds, [])
        self.assertEqual(len(problems), 1)

    def test_rpm_file_list_failure_is_a_problem(self):
        for files in (None, ""):  # demo run 8: a bad --qf made rpm print nothing, exit 0
            with self.subTest(files=files):
                builds, problems = c.from_rpm(("almalinux", "9"), fake_runner({"rpm -qa": RPM_OUT, "rpm -q": files}))
                self.assertEqual((builds, len(problems)), ([], 1))

    def test_rpm_file_query_repeats_the_name_per_file(self):
        # Real rpm (EL9) rejects [%{NAME}\t%{FILENAMES}] as different-sized arrays.
        seen = []
        c.from_rpm(("almalinux", "9"), lambda cmd: seen.append(cmd) or (RPM_OUT if "-qa" in cmd else RPM_FILES))
        self.assertIn("[%{=NAME}\t%{FILENAMES}\n]", seen[1])

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

    def test_root_skips_user_writable_dirs(self):
        import importlib
        try:
            with patch("os.geteuid", return_value=0):
                self.assertEqual(importlib.reload(c)._PATH, "/usr/bin:/bin")
            with patch("os.geteuid", return_value=501):
                self.assertIn("/opt/homebrew/bin", importlib.reload(c)._PATH)
        finally:
            importlib.reload(c)


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
        # Review: PHP_VERSION alone (set by hand next to a distro PHP) read as proof.
        (builds, problems), _ = self.docker(
            ("sha256:a", ["php:8.5-fpm"], ["PHP_VERSION=8.5.12", "PHP_SHA256=ab"]),
            ("sha256:b", ["acme/app:1"], ["PATH=/x", "PHP_VERSION=8.5.11", "PHP_SHA256=cd"]),
            ("sha256:d", ["acme/apt-php:1"], ["PHP_VERSION=8.3.36"]),
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


def fake_proc(root, pid, exe=None, maps=(), proot=None, old=b"old code", userns="user:[4026531837]"):
    """A /proc/PID entry; proot is the process's root filesystem (a container's).

    exe and each path in maps get a maps line and a map_files entry. A
    missing file is created in proot. A path ending in ' (deleted)' maps
    another inode holding `old`, as after an upgrade."""
    proot = proot or root
    d = os.path.join(root, "proc", str(pid))
    os.makedirs(os.path.join(d, "map_files"))
    os.symlink(proot, os.path.join(d, "root"))
    os.makedirs(os.path.join(d, "ns"))
    os.symlink(userns, os.path.join(d, "ns/user"))
    if not os.path.lexists(os.path.join(root, "proc/self/ns/user")):  # the scanner's own
        os.makedirs(os.path.join(root, "proc/self/ns"), exist_ok=True)
        os.symlink("user:[4026531837]", os.path.join(root, "proc/self/ns/user"))
    write(root, f"proc/{pid}/stat", f"{pid} (a) b) S {'0 ' * 18}4242 0\n")  # ')' in the name too
    lines = []
    if exe:
        os.symlink(exe, os.path.join(d, "exe"))
    for i, p in enumerate(([exe] if exe else []) + list(maps)):
        path, deleted = p.removesuffix(" (deleted)"), p.endswith(" (deleted)")
        disk = os.path.join(proot, path.lstrip("/"))
        if not os.path.exists(disk):
            write(proot, path.lstrip("/"), INSTALLED.decode())
        st = os.stat(disk)
        rng = f"7f{i:02x}0000-7f{i:02x}1000"
        lines.append(f"{rng} r-xp 00000000 {os.major(st.st_dev):02x}:{os.minor(st.st_dev):02x} "
                     f"{st.st_ino + deleted}   {p}")
        with open(os.path.join(d, "map_files", rng), "wb") as fh, open(disk, "rb") as src:
            fh.write(old if deleted else src.read())
    write(root, f"proc/{pid}/maps", "\n".join(lines) + "\n")
    return d


def ubuntu_host():
    root = root_with_dpkg(DPKG)
    write(root, "etc/os-release", 'ID=ubuntu\nVERSION_ID="24.04"\n')
    write(root, "var/lib/dpkg/info/php8.3-fpm.list", "/.\n/usr/sbin/php-fpm8.3\n")
    write(root, "var/lib/dpkg/info/php8.3-cli.list", "/usr/bin/php8.3")  # no trailing newline
    write(root, "var/lib/dpkg/info/libapache2-mod-php8.3:amd64.list",
          "/usr/lib/apache2/modules/libphp8.3.so\n")
    fake_proc(root, 1, "/usr/lib/systemd/systemd")
    return root


class TestWorkers(unittest.TestCase):
    def setUp(self):
        self.root = ubuntu_host()
        self.builds = c.from_dpkg(("ubuntu", "24.04"), self.root)[0]
        for p in (patch.object(c.os, "geteuid", return_value=0),
                  patch.object(c, "_root_owned", return_value=True)):
            p.start()
            self.addCleanup(p.stop)

    def workers(self, runner=fake_runner({})):
        return c.running_workers(self.root, self.builds, runner)[:3]

    def test_stale_worker(self):
        fake_proc(self.root, 101, "/usr/sbin/php-fpm8.3 (deleted)")
        fake_proc(self.root, 102, "/usr/sbin/php-fpm8.3")
        fake_proc(self.root, 103, "/usr/sbin/nginx")
        fake_proc(self.root, 2)                       # kernel thread: no exe
        procs, extra, problems = self.workers()
        self.assertEqual({(p["pid"], p["stale"]) for p in procs}, {("101", True), ("102", False)})
        self.assertEqual((extra, problems), ([], []))

    def test_apache_mod_php(self):
        # Audit: Apache running mod_php used to be ignored, so a stale
        # libphp after an upgrade went unreported.
        fake_proc(self.root, 200, "/usr/sbin/apache2", maps=["/usr/lib/apache2/modules/libphp8.3.so (deleted)"])
        fake_proc(self.root, 201, "/usr/sbin/apache2", maps=["/usr/lib/x.so"])
        procs, _, problems = self.workers()
        self.assertEqual([(p["pid"], p["stale"]) for p in procs], [("200", True)])
        self.assertEqual(problems, [])

    def test_suse_mod_php_and_rpm_owner(self):
        # Review: SUSE's httpd-prefork and mod_php8.so were not recognized.
        with patch.object(c, "_which", return_value="/usr/bin/rpm"):
            self.builds = c.from_rpm(("sles", "15.7"), fake_runner(
                {"rpm -qa": "apache2-mod_php8\t(none):8.3.36-150700.3.24.1", "rpm -q": RPM_FILES}))[0]
            runner = fake_runner({"rpm -qf": "apache2-mod_php8 (none):8.3.36-150700.3.24.1\n", "rpm -V": ""})
        self.assertEqual([b["package"] for b in self.builds], ["php8"])
        fake_proc(self.root, 300, "/usr/sbin/httpd-prefork", maps=["/usr/lib64/apache2/mod_php8.so (deleted)"])
        procs, _, problems = self.workers(runner)
        self.assertEqual([(p["pid"], p["stale"]) for p in procs], [("300", True)])
        self.assertEqual(problems, [])

    def test_php_cli_daemon_is_a_worker(self):
        # Review: a long-running php8.3 CLI process was not seen at all.
        fake_proc(self.root, 400, "/usr/bin/php8.3")
        procs, _, problems = self.workers()
        self.assertEqual(([p["pid"] for p in procs], problems), (["400"], []))

    def test_php_not_installed_by_a_checked_build_is_a_problem(self):
        # Audit: PHP running from outside any checked build exited 0.
        # Review: so did /usr/local/php83 without DirectAdmin and an
        # apxs-installed libphp.so, because only the path prefix was checked.
        fake_proc(self.root, 42, "/usr/local/bin/php-fpm")
        fake_proc(self.root, 43, "/usr/local/php83/sbin/php-fpm")
        fake_proc(self.root, 44, "/usr/sbin/apache2", maps=["/usr/lib/apache2/modules/libphp.so"])
        procs, _, problems = self.workers()
        self.assertEqual(procs, [])
        self.assertEqual(len(problems), 3)

    def test_source_build_needs_root_owned_header(self):
        write(self.root, "usr/local/php83/sbin/php-fpm", "")
        write(self.root, "usr/local/php83/include/php/main/php_version.h", '#define PHP_VERSION "8.3.36"\n')
        fake_proc(self.root, 50, "/usr/local/php83/sbin/php-fpm")
        _, extra, problems = self.workers()
        self.assertEqual([(b["vendor"], b["version"]) for b in extra], [("upstream", "8.3.36")])
        self.assertEqual(problems, [])
        with patch.object(c, "_root_owned", return_value=False):
            self.assertEqual(len(self.workers()[2]), 1)

    def test_container_checked_against_its_own_packages(self):
        # Review: any other mount namespace was assumed to be Docker and skipped.
        box = root_with_dpkg(dpkg_status(("php8.2-fpm", "8.2.35-1~deb12u1", OK)))
        write(box, "etc/os-release", 'ID=debian\nVERSION_ID="12"\n')
        write(box, "var/lib/dpkg/info/php8.2-fpm.list", "/usr/sbin/php-fpm8.2\n")
        fake_proc(self.root, 60, "/usr/sbin/php-fpm8.2", proot=box)
        fake_proc(self.root, 61, "/srv/legacy/php-7.2/sbin/php-fpm", proot=box)
        procs, extra, problems = self.workers()
        self.assertEqual([(b["vendor"], b["stream"], b["package"]) for b in extra], [("debian", "12", "php8.2")])
        self.assertEqual([p["pid"] for p in procs], ["60"])
        self.assertEqual(len(problems), 1)
        self.assertIn("/srv/legacy", problems[0])

    def test_user_cannot_fake_a_restart_needed(self):
        # Review: a user's deleted php-fpm forced exit 1.
        fake_proc(self.root, 70, "/home/eve/php-fpm (deleted)")
        procs, _, problems = self.workers()
        self.assertEqual((procs, len(problems)), ([], 1))

    def test_non_root_is_a_problem(self):
        # Review: with hidepid, other users' processes are invisible, not unreadable.
        with patch.object(c.os, "geteuid", return_value=1000):
            self.assertTrue(any("not run as root" in p for p in self.workers()[2]))

    def test_unreadable_is_a_problem(self):
        # Audit: unreadable processes were only a printed note.
        fake_proc(self.root, 300, "/usr/sbin/php-fpm8.3")
        with patch.object(c.os, "readlink", side_effect=PermissionError):
            self.assertTrue(any("unreadable" in p for p in self.workers()[2]))

    def test_no_proc_is_a_problem(self):
        self.assertEqual(len(c.running_workers(tempfile.mkdtemp())[2]), 1)


class TestCollect(unittest.TestCase):
    def setUp(self):
        self.root = ubuntu_host()
        for p in (patch.object(c, "_which", return_value=None),
                  patch.object(c.os, "geteuid", return_value=0)):
            p.start()
            self.addCleanup(p.stop)

    def test_dedupes_binaries_of_same_build(self):
        inv = c.collect(self.root, fake_runner({}))
        self.assertEqual(len(inv["builds"]), 2)  # ubuntu php8.3 + sury php8.5
        self.assertIn("php8.3-fpm, php8.3-cli", inv["builds"][0]["where"])
        self.assertEqual(inv["problems"], [])

    def test_no_php_is_a_problem(self):
        # Review: a host with nothing found exited 0.
        from phpfixed.resolve import load_records, resolve
        os.remove(os.path.join(self.root, "var/lib/dpkg/status"))
        fake_proc(self.root, 50, "/usr/sbin/php-fpm8.3")
        inv = c.collect(self.root, fake_runner({}))
        problems = resolve(inv, load_records(), ["CVE-2026-109618"])["problems"]
        self.assertIn("no PHP build found", problems)
        self.assertTrue(any("pid 50" in p for p in problems))


class TestPanelRuntime(unittest.TestCase):
    """Demo 1b: cPanel installs ea-php82-runtime 8.2.35 next to an 8.2.34
    PHP. The runtime package carries no PHP code. Fixture versions and
    record only; no real ea-php record exists."""

    RPM = "\n".join([
        "ea-php82-php-cli\t(none):8.2.34-1.1.1.cpanel",
        "ea-php82-php-fpm\t(none):8.2.34-1.1.1.cpanel",
        "ea-php82-runtime\t(none):8.2.35-1.2.1.cpanel",
    ])
    RECORD = {"cve": "CVE-TEST-0001", "vendor": "cpanel", "stream": "*", "package": "ea-php82",
              "branch": "8.2", "match": "vercmp-rpm", "fixed": "8.2.35-1.1.1.cpanel", "status": "fixed",
              "origin": r"^8\.2\.\d+-\d+\.\d+\.\d+\.cpanel$",
              "evidence_url": "https://example.invalid/ea4", "checked": "2026-10-29", "module": "php"}

    FILES = "\n".join([
        "ea-php82-php-cli\t/opt/cpanel/ea-php82/root/usr/bin/php",
        "ea-php82-php-fpm\t/opt/cpanel/ea-php82/root/usr/sbin/php-fpm",
        "ea-php82-runtime\t/etc/scl/prefixes/ea-php82",   # from demo eaphp-runtime-files.txt
        "ea-php82-runtime\t/opt/cpanel/ea-php82/enable",
        "ea-php82-runtime\t/opt/cpanel/ea-php82/root/usr/bin",
        "ea-php82-runtime\t/opt/cpanel/ea-php82/root/usr/share/man/man7/ea-php82.7.gz",
    ])

    def report(self):
        from phpfixed.resolve import resolve
        root = tempfile.mkdtemp()
        write(root, "etc/os-release", 'ID=almalinux\nVERSION_ID="9.8"\n')
        fake_proc(root, 10, "/opt/cpanel/ea-php82/root/usr/sbin/php-fpm")
        which = {"rpm": "/usr/bin/rpm"}.get
        with patch.object(c, "_which", side_effect=which), \
                patch.object(c.os, "geteuid", return_value=0), \
                patch.object(c, "_root_owned", return_value=True):
            inv = c.collect(root, fake_runner({"rpm -qa": self.RPM, "rpm -q": self.FILES, "rpm -V": "",
                                              "rpm -qf": "ea-php82-php-fpm (none):8.2.34-1.1.1.cpanel\n"}))
        return resolve(inv, [self.RECORD], ["CVE-TEST-0001"])

    def test_runtime_fix_record_does_not_fix_cli_or_running_php(self):
        from phpfixed.resolve import exit_code
        report = self.report()
        php = [r for r in report["results"] if "php-cli" in r["build"]["where"]]
        self.assertEqual([r["status"] for r in php], ["not-fixed"])
        self.assertIn("php-fpm", php[0]["build"]["where"])  # the running fpm's build
        self.assertEqual(report["problems"], [])            # pid 10 traced to it
        self.assertNotEqual(exit_code(report), 0)

    def test_runtime_package_never_reads_fixed(self):
        # Open risk 2: the runtime package read "fixed" next to an unfixed PHP.
        results = self.report()["results"]
        self.assertEqual([r["status"] for r in results], ["not-fixed"])
        self.assertNotIn("runtime", results[0]["build"]["where"])


if __name__ == "__main__":
    unittest.main()


OPENSSL = {"cve": "CVE-TEST-0002", "module": "openssl", "vendor": "debian", "stream": "12",
           "package": "libssl3", "branch": "3.0", "file": "libcrypto.so.3", "match": "vercmp-deb",
           "fixed": "3.0.14-1~deb12u2", "status": "fixed", "origin": r"^3\.0\.\d+-\d+~deb12u\d+$",
           "evidence_url": "https://example.invalid/dsa", "checked": "2026-10-29"}
LIB = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3"


class TestLibraries(unittest.TestCase):
    """Library files named by records, traced from /proc/PID/maps."""

    def setUp(self):
        for p in (patch.object(c, "_which", return_value=None),
                  patch.object(c.os, "geteuid", return_value=0)):
            p.start()
            self.addCleanup(p.stop)

    def host(self, version="3.0.14-1~deb12u2", root=None, lst=LIB):
        root = root or tempfile.mkdtemp()
        write(root, "etc/os-release", 'ID=debian\nVERSION_ID="12"\n')
        write(root, "var/lib/dpkg/status", dpkg_status(("libssl3", version, OK)))
        write(root, "var/lib/dpkg/info/libssl3:amd64.list", f"/.\n{lst}\n")
        write(root, "var/lib/dpkg/info/libssl3:amd64.md5sums", md5sums(lst))
        return root

    def report(self, root):
        from phpfixed.resolve import resolve
        inv = c.collect(root, fake_runner({}), libs={"libssl3": "openssl"}, files={"libcrypto.so.3": "openssl"})
        return resolve(inv, [OPENSSL], ["CVE-TEST-0002"])

    def statuses(self, report):
        return [(r["status"], r.get("mapping", {}).get("pid")) for r in report["results"]]

    def test_mapped_old_code_is_restart_needed_not_not_fixed(self):
        from phpfixed.resolve import exit_code
        root = self.host()
        fake_proc(root, 469, "/usr/bin/openssl", maps=[LIB + " (deleted)"])
        r = self.report(root)
        m = next(x for x in r["results"] if x.get("mapping"))
        self.assertEqual((m["status"], m["reason"]), ("restart-needed", "in-memory version unknown, restart needed"))
        self.assertNotEqual(m["mapping"]["mapped_sha256"], m["mapping"]["installed_sha256"])
        self.assertEqual((m["build"]["version"], m["record"]["evidence_url"], m["mapping"]["start"]),
                         ("3.0.14-1~deb12u2", "https://example.invalid/dsa", "4242"))
        self.assertEqual(exit_code(r), 1)

    def test_identical_bytes_after_reinstall_is_fixed(self):
        # A deleted mapping is not old code by itself: libssl.so.3 was byte-identical in the demo.
        from phpfixed.resolve import exit_code
        root = self.host()
        fake_proc(root, 5, "/usr/bin/openssl", maps=[LIB + " (deleted)"], old=b"installed code")
        r = self.report(root)
        self.assertEqual(self.statuses(r), [("fixed", None), ("fixed", "5")])
        self.assertEqual(exit_code(r), 0)

    def test_deleted_suffix_alone_decides_nothing(self):
        # A file literally named '... (deleted)' with the installed inode is the installed file.
        root = self.host()
        d = fake_proc(root, 6, "/usr/bin/openssl", maps=[LIB + " (deleted)"])
        st = os.stat(os.path.join(root, LIB.lstrip("/")))
        with open(os.path.join(d, "maps")) as fh:
            text = fh.read().replace(f" {st.st_ino + 1} ", f" {st.st_ino} ")
        write(root, "proc/6/maps", text)
        self.assertEqual(self.statuses(self.report(root))[1], ("fixed", "6"))

    def test_unreadable_mapped_file_is_unknown_never_fixed(self):
        from phpfixed.resolve import exit_code
        root = self.host()
        d = fake_proc(root, 7, "/usr/bin/openssl", maps=[LIB + " (deleted)"])
        for f in os.listdir(os.path.join(d, "map_files")):
            os.remove(os.path.join(d, "map_files", f))
        r = self.report(root)
        self.assertEqual(self.statuses(r), [("fixed", None)])
        self.assertTrue(any("pid 7: can't compare" in p for p in r["problems"]))
        self.assertEqual(exit_code(r), 2)

    def test_oversize_mapped_file_is_unknown(self):
        root = self.host()
        fake_proc(root, 8, "/usr/bin/openssl", maps=[LIB + " (deleted)"], old=b"x" * 2000)
        with patch.object(c, "MAX_READ", 1000):  # every fixture file fits, the mapped one doesn't
            self.assertTrue(any("pid 8: can't compare" in p for p in self.report(root)["problems"]))

    def test_map_files_name_drops_zero_padding(self):
        root = self.host()
        d = fake_proc(root, 9, "/usr/bin/openssl", maps=[LIB + " (deleted)"])
        with open(os.path.join(d, "maps")) as fh:
            write(root, "proc/9/maps", fh.read().replace("7f000000-7f001000", "00400000-00452000"))
        os.rename(os.path.join(d, "map_files", "7f000000-7f001000"), os.path.join(d, "map_files", "400000-452000"))
        self.assertEqual(self.statuses(self.report(root))[1], ("restart-needed", "9"))

    def test_untraced_library_is_a_problem(self):
        from phpfixed.resolve import exit_code
        root = self.host()
        fake_proc(root, 10, "/opt/app/bin/app", maps=["/opt/app/lib/libcrypto.so.3"])
        r = self.report(root)
        self.assertTrue(any("pid 10 runs /opt/app/lib/libcrypto.so.3" in p for p in r["problems"]))
        self.assertEqual(exit_code(r), 2)

    def test_merged_usr_list_path_resolved_in_process_root(self):
        # dpkg lists /lib/...; the kernel shows /usr/lib/... because /lib -> usr/lib.
        for target in ("usr/lib", "/usr/lib"):  # relative, and absolute inside the root
            with self.subTest(target=target):
                root = self.host(lst="/lib/x86_64-linux-gnu/libcrypto.so.3")
                os.symlink(target, os.path.join(root, "lib"))
                fake_proc(root, 11, "/usr/bin/openssl", maps=[LIB])
                r = self.report(root)
                self.assertEqual((self.statuses(r)[1], r["problems"]), (("fixed", "11"), []))

    def test_symlink_loop_in_root_is_untraced(self):
        root = self.host(lst="/lib/x86_64-linux-gnu/libcrypto.so.3")
        os.symlink("lib", os.path.join(root, "lib"))
        self.assertIsNone(c._in_root(root, "/lib/x86_64-linux-gnu/libcrypto.so.3"))

    def test_absolute_symlink_stays_inside_process_root(self):
        box = tempfile.mkdtemp()
        os.makedirs(os.path.join(box, "usr/lib"))
        os.symlink("/usr/lib", os.path.join(box, "lib"))
        os.symlink("/etc", os.path.join(box, "usr/lib/up"))
        self.assertEqual(c._in_root(box, "/lib/up/../x"), "/x")
        self.assertEqual(c._in_root(box, "/lib/../../../etc/passwd"), "/etc/passwd")

    def test_receipt_names_package_database(self):
        root = self.host()
        box = self.host(version="3.0.14-1~deb12u1")
        fake_proc(root, 12, "/usr/bin/openssl", maps=[LIB])
        fake_proc(root, 13, "/usr/bin/openssl", maps=[LIB], proot=box)
        got = {r["mapping"]["pid"]: (r["status"], r["build"]["db"]) for r in self.report(root)["results"]
               if r.get("mapping")}
        self.assertEqual(got, {"12": ("fixed", "host"), "13": ("not-fixed", "container")})

    def test_thirdparty_rebuild_with_higher_version_is_unknown(self):
        root = self.host(version="3.0.14-1+thirdparty1")
        fake_proc(root, 14, "/usr/bin/openssl", maps=[LIB])
        self.assertEqual(self.statuses(self.report(root)), [("unknown", None), ("unknown", "14")])

    def test_process_gone_mid_scan_is_skipped(self):
        # The pinned fd fails once the process exits; its reads are dropped.
        root = self.host()
        fake_proc(root, 15, "/usr/bin/openssl", maps=[LIB + " (deleted)"])
        real, calls = c._read, []

        def read(d, name):
            calls.append(name)
            if name == "stat" and calls.count("stat") >= 2:  # gone, and stays gone
                raise ProcessLookupError(3, "No such process")
            return real(d, name)
        with patch.object(c, "_read", side_effect=read):
            r = self.report(root)
        self.assertEqual((self.statuses(r), r["problems"]), ([("fixed", None)], []))

    def test_every_libcrypto_copy_is_a_subject(self):
        # Review #1: a renamed bundled copy (auditwheel) was never looked at.
        files = {"libcrypto.so.3": "openssl"}
        for path in ("/usr/lib64/libcrypto.so.3.5.8", "/opt/app/libs/libcrypto-1a2b3c4d.so.3",
                     "/memfd:libcrypto.so.3 (deleted)", "/usr/lib/libcrypto.so.1.1", "/usr/lib/libcrypto.so"):
            self.assertEqual(c._lib_file(path, files), "libcrypto.so.3", path)
        for path in ("/usr/lib/libcryptopp.so.8", "/usr/lib/libcryptsetup.so.12", "/usr/lib/libcrypto.a"):
            self.assertIsNone(c._lib_file(path, files), path)

    def test_bundled_copy_is_untraced_and_named(self):
        from phpfixed.resolve import exit_code
        root = self.host()
        fake_proc(root, 16, "/usr/bin/python3", maps=["/opt/app/libs/libcrypto-1a2b3c4d.so.3"])
        r = self.report(root)
        self.assertIn("pid 16 runs /opt/app/libs/libcrypto-1a2b3c4d.so.3, which no checked package or build "
                      "installed: bundled copy, not owned by a package", r["problems"])
        self.assertEqual(exit_code(r), 2)

    def test_copy_owned_by_a_package_without_record_says_so(self):
        root = self.host()
        write(root, "var/lib/dpkg/info/libssl1.1:amd64.list", "/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1\n")
        fake_proc(root, 17, "/usr/bin/legacy", maps=["/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1"])
        self.assertTrue(any("owned by libssl1.1:amd64, which no record covers" in p for p in self.report(root)["problems"]))

    def test_rpm_library_package_needs_no_php_file(self):
        with patch.object(c, "_which", return_value="/usr/bin/rpm"):
            builds, problems = c.from_rpm(("almalinux", "9"), fake_runner(
                {"rpm -qa": "openssl-libs\t1:3.5.8-2.el9_8"}), libs={"openssl-libs": "openssl"})
        self.assertEqual([(b["package"], b["module"], b["branch"]) for b in builds],
                         [("openssl-libs", "openssl", "3.5")])
        self.assertEqual(problems, [])

    def test_modules_do_not_cross(self):
        # PHP builds get no OpenSSL rows and the other way round; a missing module is a problem.
        from phpfixed.resolve import load_records, resolve
        root = self.host()
        inv = c.collect(root, fake_runner({}), libs={"libssl3": "openssl"}, files={"libcrypto.so.3": "openssl"})
        r = resolve(inv, load_records() + [OPENSSL], ["CVE-2026-109618", "CVE-TEST-0002"])
        self.assertEqual({(x["cve"], x["build"]["package"]) for x in r["results"]}, {("CVE-TEST-0002", "libssl3")})
        self.assertIn("no PHP build found", r["problems"])

    def test_scope_names_what_is_checked(self):
        r = self.report(self.host())
        self.assertEqual(r["limits"], ["libcrypto.so.3: every mapped libcrypto*.so* file is checked; "
                                       "a copy linked statically into a program is not seen"])


class TestPackageConsistency(unittest.TestCase):
    """Review finding #2: the installed file must be the package's own copy."""

    def setUp(self):
        for p in (patch.object(c, "_which", return_value=None), patch.object(c.os, "geteuid", return_value=0)):
            p.start()
            self.addCleanup(p.stop)

    def problems(self, root):
        from phpfixed.resolve import resolve
        inv = c.collect(root, fake_runner({}), libs={"libssl3": "openssl"}, files={"libcrypto.so.3": "openssl"})
        return [r for r in resolve(inv, [OPENSSL], ["CVE-TEST-0002"])["results"] if r.get("mapping")], inv["problems"]

    def test_dpkg_diverted_file_is_untraced(self):
        root = TestLibraries.host(None)
        write(root, "var/lib/dpkg/diversions", f"{LIB}\n{LIB}.distrib\n:\n")
        fake_proc(root, 20, "/usr/bin/openssl", maps=[LIB])
        mapped, problems = self.problems(root)
        self.assertEqual((mapped, len(problems)), ([], 1))
        self.assertIn("diverted", problems[0])

    def test_file_differing_from_md5sums_is_untraced(self):
        root = TestLibraries.host(None)
        fake_proc(root, 21, "/usr/bin/openssl", maps=[LIB])
        write(root, LIB.lstrip("/"), "admin's own build")  # same path, other bytes, new inode
        mapped, problems = self.problems(root)
        self.assertEqual(mapped, [])
        self.assertTrue(any("differs from dpkg's md5sum" in p for p in problems))

    def test_missing_md5sums_is_untraced(self):
        root = TestLibraries.host(None)
        os.remove(os.path.join(root, "var/lib/dpkg/info/libssl3:amd64.md5sums"))
        fake_proc(root, 22, "/usr/bin/openssl", maps=[LIB])
        mapped, problems = self.problems(root)
        self.assertEqual(mapped, [])
        self.assertTrue(any("no md5sum" in p for p in problems))

    def test_rpm_file_must_pass_rpm_verify(self):
        lib = "/usr/lib64/libcrypto.so.3.5.8"
        for verify, traced in (("", True), (f"S.5....T.    {lib}\n", False), (f".......T.    {lib}\n", True),
                               ("package openssl-libs is not installed\n", False), (None, False)):
            with self.subTest(verify=verify):
                root = tempfile.mkdtemp()
                write(root, "etc/os-release", 'ID=almalinux\nVERSION_ID="9.8"\n')
                fake_proc(root, 23, "/usr/bin/openssl", maps=[lib])
                runner = fake_runner({"rpm -qa": "openssl-libs\t1:3.5.8-2.el9_8", "rpm -qf": "openssl-libs 1:3.5.8-2.el9_8\n",
                                      "rpm -V": verify})
                with patch.object(c, "_which", return_value="/usr/bin/rpm"):
                    inv = c.collect(root, runner, libs={"openssl-libs": "openssl"}, files={"libcrypto.so.3": "openssl"})
                self.assertEqual(bool(inv["mappings"]), traced)
                self.assertEqual(any("fails rpm -V" in p for p in inv["problems"]), not traced)


class TestHostileFiles(unittest.TestCase):
    """Review #4 and #9: files a container controls can't block, flood or
    abort the scan, and its absolute symlinks resolve inside it."""

    def setUp(self):
        import signal
        for p in (patch.object(c, "_which", return_value=None), patch.object(c.os, "geteuid", return_value=0)):
            p.start()
            self.addCleanup(p.stop)

        def timeout(*_):
            raise KeyboardInterrupt("scan blocked")  # not an OSError, so the code can't swallow it
        signal.signal(signal.SIGALRM, timeout)
        signal.alarm(5)  # old code blocks forever on a FIFO
        self.addCleanup(signal.alarm, 0)

    def box_scan(self, prep):
        root, box = TestLibraries.host(None), TestLibraries.host(None)
        fake_proc(root, 30, "/usr/bin/openssl", maps=[LIB + " (deleted)"], proot=box)
        prep(box)
        return c.collect(root, fake_runner({}), libs={"libssl3": "openssl"}, files={"libcrypto.so.3": "openssl"})

    def test_container_fifo_database_does_not_block(self):
        def prep(box):
            os.remove(os.path.join(box, "var/lib/dpkg/status"))
            os.mkfifo(os.path.join(box, "var/lib/dpkg/status"))
        inv = self.box_scan(prep)
        self.assertEqual(inv["mappings"], [])
        self.assertTrue(any("pid 30" in p for p in inv["problems"]))

    def test_installed_file_replaced_by_fifo_does_not_block(self):
        def prep(box):
            os.remove(os.path.join(box, LIB.lstrip("/")))
            os.mkfifo(os.path.join(box, LIB.lstrip("/")))
        inv = self.box_scan(prep)
        self.assertEqual(inv["mappings"], [])
        self.assertTrue(any("pid 30" in p and "can't be checked" in p for p in inv["problems"]))

    def test_absolute_symlink_in_container_resolves_inside_it(self):
        box = tempfile.mkdtemp()
        write(box, "etc/inside", "container's file")
        os.makedirs(os.path.join(box, "var"))
        os.symlink("/etc/inside", os.path.join(box, "var/link"))
        self.assertEqual(c._slurp(box, "/var/link"), b"container's file")
        os.symlink("/etc/hosts", os.path.join(box, "var/host"))  # exists on the scanner's host only
        with self.assertRaises(FileNotFoundError):
            c._slurp(box, "/var/host")

    def test_size_zero_file_is_not_read(self):
        # /proc/kmsg reports size 0; reading it would drain the kernel log.
        box = tempfile.mkdtemp()
        write(box, "kmsg", "")
        with patch.object(c.os, "read", side_effect=AssertionError("read")):
            self.assertEqual(c._slurp(box, "/kmsg"), b"")

    def test_non_utf8_container_os_release_does_not_abort(self):
        def prep(box):
            with open(os.path.join(box, "etc/os-release"), "wb") as fh:
                fh.write(b'ID=debian\xff\nVERSION_ID="12"\n')
        inv = self.box_scan(prep)
        self.assertEqual([m["build"]["db"] for m in inv["mappings"]], ["container"])


class TestReviewSmallFixes(unittest.TestCase):
    """Review findings #5 to #8."""

    def setUp(self):
        for p in (patch.object(c, "_which", return_value=None), patch.object(c.os, "geteuid", return_value=0)):
            p.start()
            self.addCleanup(p.stop)

    def test_container_os_release_id_is_escaped_in_table(self):
        # #5: a container's ID could redraw a host [NOT-FIXED] line as [FIXED].
        import contextlib
        import io
        from phpfixed import cli
        root, box = TestLibraries.host(None, version="3.0.14-1~deb12u1"), TestLibraries.host(None)
        write(box, "etc/os-release", 'ID="debian\x1b[3A\x1b[2K[FIXED]"\nVERSION_ID="12"\n')
        fake_proc(root, 30, "/usr/bin/openssl", maps=[LIB], proot=box)
        r = TestLibraries.report(None, root)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli._table({"os": {"id": "debian", "stream": "12"}}, r)
        self.assertNotIn("\x1b", out.getvalue())

    def test_every_inode_of_a_path_is_checked(self):
        # #6: two deleted inodes, old code first and identical bytes second, read "fixed".
        root = TestLibraries.host(None)
        d = fake_proc(root, 40, "/usr/bin/openssl", maps=[LIB + " (deleted)", LIB + " (deleted)"])
        rngs = sorted(os.listdir(os.path.join(d, "map_files")))
        with open(os.path.join(d, "map_files", rngs[-1]), "wb") as fh:
            fh.write(INSTALLED)
        lines = open(os.path.join(d, "maps")).read().splitlines()
        ino = int(lines[-1].split()[4])
        lines[-1] = lines[-1].replace(f" {ino} ", f" {ino + 1} ")
        write(root, "proc/40/maps", "\n".join(lines) + "\n")
        got = sorted(r["status"] for r in TestLibraries.report(None, root)["results"] if r.get("mapping"))
        self.assertEqual(got, ["fixed", "restart-needed"])

    def test_packaged_path_now_a_symlink_owns_nothing_else(self):
        # #7: the list's libcrypto.so.3 is a symlink to a vendor build; the vendor file isn't libssl3's.
        root = TestLibraries.host(None)
        # Same bytes as the package's copy, so only ownership decides (#2's md5 check passes).
        write(root, "opt/vendor/lib/libcrypto.so.3", INSTALLED.decode())
        os.makedirs(os.path.dirname(os.path.join(root, LIB.lstrip("/"))))
        os.symlink("/opt/vendor/lib/libcrypto.so.3", os.path.join(root, LIB.lstrip("/")))
        fake_proc(root, 50, "/usr/bin/openssl", maps=["/opt/vendor/lib/libcrypto.so.3"])
        r = TestLibraries.report(None, root)
        self.assertEqual([x for x in r["results"] if x.get("mapping")], [])
        self.assertTrue(any("pid 50" in p for p in r["problems"]))

    def test_php_module_in_any_process_is_a_worker(self):
        # #8: uWSGI's PHP plugin mapping a stale libphp was not looked at.
        root = ubuntu_host()
        builds = c.from_dpkg(("ubuntu", "24.04"), root)[0]
        fake_proc(root, 71, "/usr/bin/uwsgi-core", maps=["/usr/lib/apache2/modules/libphp8.3.so (deleted)"])
        workers = c.running_workers(root, builds, fake_runner({}))[0]
        self.assertEqual([(w["pid"], w["stale"]) for w in workers], [("71", True)])


class TestReview2(unittest.TestCase):
    """Second independent review, findings #1 to #12."""

    def setUp(self):
        for p in (patch.object(c, "_which", return_value=None), patch.object(c.os, "geteuid", return_value=0)):
            p.start()
            self.addCleanup(p.stop)

    def scan(self, root, records=(OPENSSL,), runner=None, libs={"libssl3": "openssl"}):
        from phpfixed.resolve import exit_code, resolve
        files = {r["file"]: r["module"] for r in records if r.get("file")}
        inv = c.collect(root, runner or fake_runner({}), libs=libs, files=files)
        r = resolve(inv, list(records), [x["cve"] for x in records][:1])
        return r, exit_code(r)

    def container(self, box, maps=(LIB,), host=None):
        """A host (empty unless given) and pid 100 running inside the container root box."""
        if host is None:
            host = tempfile.mkdtemp()
            write(host, "etc/os-release", 'ID=debian\nVERSION_ID="12"\n')
        fake_proc(host, 100, "/usr/bin/openssl", maps=list(maps), proot=box)
        return host

    def test_container_package_state_problem_is_kept(self):
        # #1: a half-installed libssl3 in a container read fixed, exit 0.
        box = TestLibraries.host(None)
        write(box, "var/lib/dpkg/status", dpkg_status(("libssl3", "3.0.14-1~deb12u2", "install ok half-installed")))
        r, code = self.scan(self.container(box))
        self.assertTrue(any(p.startswith("container of pid 100: dpkg state of libssl3") for p in r["problems"]))
        self.assertEqual(code, 2)

    def test_container_php_package_state_problem_is_kept(self):
        from phpfixed.resolve import exit_code, load_records, resolve
        box = root_with_dpkg(dpkg_status(("php8.2-fpm", "8.2.35-1~deb12u1", "install ok half-installed")))
        write(box, "etc/os-release", 'ID=debian\nVERSION_ID="12"\n')
        host = tempfile.mkdtemp()
        fake_proc(host, 100, "/usr/sbin/php-fpm8.2", proot=box)
        r = resolve(c.collect(host, fake_runner({})), load_records(), ["CVE-2026-109618"])
        self.assertTrue(any(p.startswith("container of pid 100: dpkg state of php8.2-fpm") for p in r["problems"]))
        self.assertEqual(exit_code(r), 2)

    def multiarch_root(self):
        """libssl3:amd64 fixed and libssl3:i386 vulnerable (Multi-Arch: same)."""
        root = tempfile.mkdtemp()
        write(root, "etc/os-release", 'ID=debian\nVERSION_ID="12"\n')
        write(root, "var/lib/dpkg/status", "".join(
            f"Package: libssl3\nStatus: {OK}\nArchitecture: {a}\nMulti-Arch: same\nVersion: {v}\n\n"
            for a, v in (("amd64", "3.0.14-1~deb12u2"), ("i386", "3.0.11-1~deb12u2"))))
        for a, d in (("amd64", "x86_64"), ("i386", "i386")):
            write(root, f"var/lib/dpkg/info/libssl3:{a}.list", f"/usr/lib/{d}-linux-gnu/libcrypto.so.3\n")
            write(root, f"var/lib/dpkg/info/libssl3:{a}.md5sums", md5sums(f"/usr/lib/{d}-linux-gnu/libcrypto.so.3"))
        return root

    def test_multiarch_mapping_gets_its_own_architecture(self):
        # #2: a 32-bit process mapping the vulnerable i386 libcrypto got the amd64 version.
        i386 = "/usr/lib/i386-linux-gnu/libcrypto.so.3"
        root = self.multiarch_root()
        fake_proc(root, 7, "/usr/bin/openssl32", maps=[i386])
        r, code = self.scan(root)
        self.assertEqual([(x["status"], x["build"]["where"]) for x in r["results"] if x.get("mapping")],
                         [("not-fixed", "libssl3:i386")])
        r, code = self.scan(self.container(self.multiarch_root(), maps=[i386]))
        self.assertEqual(code, 1)  # in a container the vulnerable one used to vanish: exit 0

    def test_rpm_multilib_mapping_gets_its_instance_version(self):
        rec = {**OPENSSL, "vendor": "rhel", "stream": "9", "package": "openssl-libs", "match": "vercmp-rpm",
               "fixed": "1:3.0.7-28.el9_4", "origin": r"^1:3\.0\.7-\d+\.el9(_\d+)?$"}
        root = tempfile.mkdtemp()
        write(root, "etc/os-release", 'ID=rhel\nVERSION_ID="9.4"\n')
        fake_proc(root, 9, "/usr/bin/app32", maps=["/usr/lib/libcrypto.so.3.0.7"])
        runner = fake_runner({"rpm -qa": "openssl-libs\t1:3.0.7-28.el9_4\nopenssl-libs\t1:3.0.7-24.el9\n",
                              "rpm -qf": "openssl-libs 1:3.0.7-24.el9\n", "rpm -V": ""})
        with patch.object(c, "_which", return_value="/usr/bin/rpm"):
            r, code = self.scan(root, [rec], runner, {"openssl-libs": "openssl"})
        self.assertEqual([(x["status"], x["build"]["version"]) for x in r["results"] if x.get("mapping")],
                         [("not-fixed", "1:3.0.7-24.el9")])

    def test_unexpected_read_error_is_a_problem_not_a_gone_process(self):
        # #3: a container's diversions file as a directory made pid 100 vanish; exit 0.
        host = TestLibraries.host(None)
        fake_proc(host, 1, "/usr/sbin/sshd", maps=[LIB])
        box = TestLibraries.host(None, version="3.0.14-1~deb12u1")
        os.makedirs(os.path.join(box, "var/lib/dpkg/diversions"))
        r, code = self.scan(self.container(box, host=host))
        self.assertTrue(any(p.startswith("pid 100 runs /usr/bin/openssl and was not fully checked") for p in r["problems"]))
        self.assertEqual(code, 2)

    def test_kernel_thread_and_gone_process_are_skipped(self):
        host = TestLibraries.host(None)
        fake_proc(host, 2)  # kernel thread: no exe
        r, code = self.scan(host)
        self.assertEqual(r["problems"], [])

    def test_package_change_during_scan_is_a_problem(self):
        # #4: a downgrade between the dpkg read and the /proc walk read fixed, exit 0.
        host = TestLibraries.host(None)
        real = c.running_workers

        def downgrade_then_walk(*a, **k):
            write(host, "var/lib/dpkg/status", dpkg_status(("libssl3", "3.0.14-1~deb12u1", OK)))
            return real(*a, **k)
        with patch.object(c, "running_workers", downgrade_then_walk):
            r, code = self.scan(host)
        self.assertIn("packages changed during the scan; run it again", r["problems"])
        self.assertEqual(code, 2)

    def test_process_in_another_user_namespace_is_untraced(self):
        # #5: a plain user's unshare -Urm root with a forged dpkg database read fixed, exit 0.
        box = TestLibraries.host(None)
        host = tempfile.mkdtemp()
        fake_proc(host, 4242, "/usr/bin/openssl", maps=[LIB], proot=box, userns="user:[4026532999]")
        r, code = self.scan(host)
        self.assertEqual([x for x in r["results"] if x.get("mapping")], [])
        self.assertIn(f"pid 4242 runs {LIB} in another user namespace; its packages can't be trusted", r["problems"])
        self.assertEqual(code, 2)

    def test_rpm_verify_question_mark_fails(self):
        # #9: '?' (digest not computed) in the size or digest column counted as a pass.
        lib = "/usr/lib64/libcrypto.so.3.5.8"
        for verify in (f"..?......    {lib}\n", f"?........    {lib}\n"):
            with self.subTest(verify=verify):
                root = tempfile.mkdtemp()
                write(root, "etc/os-release", 'ID=almalinux\nVERSION_ID="9.8"\n')
                fake_proc(root, 23, "/usr/bin/openssl", maps=[lib])
                runner = fake_runner({"rpm -qa": "openssl-libs\t1:3.5.8-2.el9_8", "rpm -V": verify,
                                      "rpm -qf": "openssl-libs 1:3.5.8-2.el9_8\n"})
                with patch.object(c, "_which", return_value="/usr/bin/rpm"):
                    inv = c.collect(root, runner, libs={"openssl-libs": "openssl"}, files={"libcrypto.so.3": "openssl"})
                self.assertEqual((inv["mappings"], any("fails rpm -V" in p for p in inv["problems"])), ([], True))

    def test_file_list_rewritten_mid_scan_is_untraced_not_a_crash(self):
        # #12: the second read of the list found nothing; AttributeError, exit 3.
        host = TestLibraries.host(None)
        fake_proc(host, 1, "/usr/sbin/sshd", maps=[LIB])
        real, calls = c._dpkg_owns, []

        def racy(proot, pkg, path):
            calls.append(pkg)
            return real(proot, pkg, path) if len(calls) == 1 else None
        with patch.object(c, "_dpkg_owns", racy):
            r, code = self.scan(host)
        self.assertTrue(any("dpkg no longer lists it" in p for p in r["problems"]))
        self.assertEqual(code, 2)
