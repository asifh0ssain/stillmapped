"""Find PHP builds installed on this host.

Read-only. Reads dpkg's status database, queries rpm and the local Docker
daemon's image metadata, and reads Homebrew's Cellar, DirectAdmin's installed
headers and /proc for running PHP workers. Never modifies anything, never
touches the network, never executes a binary found on disk.

Every collector returns (builds, problems). A problem is anything that kept
a part of the host from being checked; it makes the overall result unknown.
"""

import glob
import json
import os
import re
import shutil
import subprocess

from .vercmp import branch

RUN_TIMEOUT = 20  # seconds, per subprocess
# Commands are looked up here only, never on the caller's PATH, so a planted
# 'rpm' or 'docker' earlier on PATH is not run when this runs as root.
# /usr/local/bin and /opt/homebrew/bin are user-writable on a Mac, so root
# skips them.
_PATH = "/usr/bin:/bin" + ("" if os.geteuid() == 0 else ":/usr/local/bin:/opt/homebrew/bin")
# Pinning the socket stops DOCKER_HOST or a docker context from sending the
# query to another machine.
_DOCKER = ["docker", "-H", "unix:///var/run/docker.sock"]

# Binary package names that carry the PHP runtime. Extension packages
# (php8.2-mysql etc.) share the runtime's version and would only add noise.
_DEB_PKG = re.compile(r"^(?:libapache2-mod-)?(php\d+\.\d+)(?:-(?:fpm|cli|cgi|common))?$")
_RPM_BASE = re.compile(r"^(?:apache2-mod_)?(php\d?)(?:-(?:fpm|cli|common))?$")  # php, SUSE php8/php7
_RPM_SCL = re.compile(r"^(php\d\d)-php(?:-(?:fpm|cli|common))?$")          # Remi SCL
_PANEL = re.compile(r"^((?:ea|alt|plesk)-php\d\d)(?:-php)?(?:-(?:fpm|cli|common|runtime))?$")
_SURY = re.compile(r"deb\.sury\.org|\+0~\d{8}")
_PHP_VERSION_H = re.compile(r'#define PHP_VERSION "([^"]+)"')

# Processes that run PHP: PHP binaries (php8.3 CLI daemons too), and Apache
# (apache2, httpd, SUSE's httpd-prefork) or NGINX Unit with a PHP module mapped.
_PHP_EXE = re.compile(r"(php-fpm|php-cgi|lsphp|php)[\d.]*$|frankenphp$")
_EMBEDS = re.compile(r"(apache2|httpd)(-\w+)?$|unitd$")
_PHP_MODULE = re.compile(r"/(libphp|mod_php)[^/]*\.so")


def _which(name):
    return shutil.which(name, path=_PATH)


def run(cmd):
    """Run a read-only command with a minimal environment; stdout or None."""
    exe = _which(cmd[0])
    if not exe:
        return None
    try:
        p = subprocess.run([exe, *cmd[1:]], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", stdin=subprocess.DEVNULL,
                           env={"PATH": _PATH, "LC_ALL": "C"}, timeout=RUN_TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return p.stdout if p.returncode == 0 else None


def os_release(root="/"):
    """(id, stream) from /etc/os-release, e.g. ('ubuntu', '24.04'), ('rhel', '9')."""
    info = {}
    for name in ("etc/os-release", "usr/lib/os-release"):
        try:
            with open(os.path.join(root, name), encoding="utf-8") as fh:
                for line in fh:
                    k, sep, v = line.strip().partition("=")
                    if sep:
                        info[k] = v.strip().strip('"')
            break
        except OSError:
            continue
    osid = info.get("ID", "")
    ver = info.get("VERSION_ID", "")
    # Ubuntu and SUSE track fixes per X.Y (24.04, 15.7); Debian and the
    # RHEL family per major release.
    full = osid in ("ubuntu", "sles", "sled", "opensuse-leap")
    stream = ver if full else ver.split(".")[0]
    return osid, stream


def _build(source, vendor, stream, package, version, scheme, where):
    return {"source": source, "vendor": vendor, "stream": stream, "package": package,
            "branch": branch(version), "version": version, "scheme": scheme, "where": where}


def _upstream(source, version, where):
    """A build compiled from php.net source; judged by the upstream release."""
    return _build(source, "upstream", "*", "php", version, "upstream", where)


def from_dpkg(osr, root="/"):
    """Installed packages, read straight from dpkg's status database."""
    try:
        with open(os.path.join(root, "var/lib/dpkg/status"), encoding="utf-8", errors="replace") as fh:
            paragraphs = fh.read().split("\n\n")
    except FileNotFoundError:
        return [], []
    except OSError as e:
        return [], [f"dpkg database unreadable: {e.strerror}"]
    builds = []
    for para in paragraphs:
        f = dict(line.split(": ", 1) for line in para.splitlines()
                 if ": " in line and not line[0].isspace())
        # Held, reinstall-required and half-configured packages still have
        # their files on disk; only these two states don't.
        if f.get("Status", "").split()[-1:] in ([], ["not-installed"], ["config-files"]):
            continue
        name, version = f.get("Package", ""), f.get("Version", "")
        m = _DEB_PKG.match(name) or _PANEL.match(name)
        if not m:
            continue
        pkg = m.group(1)
        if pkg.startswith(("ea-", "alt-", "plesk-")):
            vendor, stream = _panel_vendor(pkg), "*"
        elif _SURY.search(version):
            vendor, stream = "sury", "*"
        else:
            vendor, stream = osr
        builds.append(_build("dpkg", vendor, stream, pkg, version, "vercmp-deb", name))
    return builds, []


def from_rpm(osr, runner=run):
    if not _which("rpm"):
        return [], []
    out = runner(["rpm", "-qa", "--qf", "%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}\n"])
    if out is None:
        return [], ["rpm is installed but its package database couldn't be read"]
    builds = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        name, evr = parts
        evr = evr.replace("(none):", "")
        if m := _PANEL.match(name):
            vendor, stream = _panel_vendor(m.group(1)), osr[1] or "*"
        elif m := _RPM_SCL.match(name):
            vendor, stream = "remi", osr[1] or "*"
        elif m := _RPM_BASE.match(name):
            vendor, stream = ("remi", osr[1]) if ".remi" in evr else osr
        else:
            continue
        builds.append(_build("rpm", vendor, stream, m.group(1), evr, "vercmp-rpm", name))
    return builds, []


def _panel_vendor(pkg):
    return {"ea": "cpanel", "alt": "cloudlinux", "plesk": "plesk"}[pkg.split("-", 1)[0]]


def from_docker(runner=run):
    """Every local image built from the official php image (which compiles
    PHP from source), found by its PHP_VERSION and PHP_SHA256. PHP_VERSION
    alone is often set by hand next to a distro PHP package, so it proves
    nothing."""
    if not _which("docker"):
        return [], []
    ids = runner(_DOCKER + ["image", "ls", "-q", "--no-trunc"])
    if ids is None:
        return [], ["docker is installed but its local daemon didn't answer; images not checked"]
    ids = sorted(set(ids.split()))
    if not ids:
        return [], []
    out = runner(_DOCKER + ["image", "inspect", "--format",
                            "{{.Id}}\t{{json .RepoTags}}\t{{json .Config.Env}}"] + ids)
    if out is None:
        return [], ["docker image inspect failed; images not checked"]
    builds = []
    try:
        for line in out.splitlines():
            image, tags, env = line.split("\t")
            tags, env = json.loads(tags) or [], json.loads(env) or []
            env = dict(p.split("=", 1) for p in env if "=" in p)
            version = env.get("PHP_VERSION")
            if version and env.get("PHP_SHA256"):
                builds.append(_upstream("docker", version, ", ".join(tags) or image))
    except (ValueError, TypeError, AttributeError):
        return builds, ["unreadable docker image metadata; images not fully checked"]
    return builds, []


def from_homebrew(root="/"):
    builds = []
    for cellar in ("opt/homebrew/Cellar", "usr/local/Cellar"):
        for d in sorted(glob.glob(os.path.join(root, cellar, "php*", "*"))):
            formula, version = d.split(os.sep)[-2:]
            if re.fullmatch(r"php(@\d+\.\d+)?", formula):  # not phpunit, phpstan...
                builds.append(_upstream("homebrew", re.sub(r"_\d+$", "", version), d))
    return builds, []


def from_directadmin(root="/"):
    """CustomBuild compiles PHP into /usr/local/phpXX. The version is read
    from the installed php_version.h header; the binary is never executed."""
    if not os.path.isdir(os.path.join(root, "usr/local/directadmin")):
        return [], []
    builds, problems = [], []
    for prefix in sorted(glob.glob(os.path.join(root, "usr/local/php[0-9]*"))):
        if not os.path.isdir(os.path.join(prefix, "bin")):
            continue
        try:
            with open(os.path.join(prefix, "include/php/main/php_version.h"), encoding="utf-8",
                      errors="replace") as fh:
                m = _PHP_VERSION_H.search(fh.read())
        except OSError:
            m = None
        if m:
            builds.append(_upstream("directadmin", m.group(1), prefix))
        else:
            problems.append(f"no readable PHP version header under {prefix}")
    return builds, problems


def _php_path(pid_dir, exe):
    """The PHP file a process runs ('(deleted)' kept): its own binary, or a
    PHP module mapped into Apache or Unit. None if it runs no PHP."""
    name = os.path.basename(exe.removesuffix(" (deleted)"))
    if _PHP_EXE.match(name):
        return exe
    if not _EMBEDS.match(name):
        return None
    with open(os.path.join(pid_dir, "maps"), encoding="utf-8", errors="replace") as fh:
        for line in fh:
            path = line.rstrip("\n").split(None, 5)[5:]
            if path and _PHP_MODULE.search(path[0]):
                return path[0]
    return None


def _root_owned(path):
    st = os.stat(path)
    return st.st_uid == 0 and not st.st_mode & 0o022


def _dpkg_owns(proot, pkg, path):
    info = os.path.join(proot, "var/lib/dpkg/info")
    for lst in [os.path.join(info, pkg + ".list"), *glob.glob(os.path.join(info, glob.escape(pkg) + ":*.list"))]:
        try:
            with open(lst, encoding="utf-8", errors="replace") as fh:
                if any(line.rstrip("\n") == path for line in fh):
                    return True
        except OSError:
            continue
    return False


def _rpm_owner(runner, path):
    """Name of the rpm package that owns path, or None."""
    out = runner(["rpm", "-qf", "--qf", "%{NAME}\n", path])
    return out.strip() if out and len(out.split()) == 1 else None


def _owner(proot, path, builds, rpm_name):
    """The build that installed the file at path, as seen from proot: a
    package that lists it, or a source build whose prefix holds it and
    whose root-owned header gives its version. None if nothing checked does."""
    prefix = os.path.dirname(os.path.dirname(path))
    for b in builds:
        if (b["where"] == prefix or b["source"] == "rpm" and b["where"] == rpm_name
                or b["source"] == "dpkg" and _dpkg_owns(proot, b["where"], path)):
            return b
    exe = os.path.join(proot, path.lstrip("/"))
    header = os.path.join(proot, prefix.lstrip("/"), "include/php/main/php_version.h")
    try:
        if _root_owned(exe) and _root_owned(header):
            with open(header, encoding="utf-8", errors="replace") as fh:
                m = _PHP_VERSION_H.search(fh.read())
            return _upstream("source", m.group(1), prefix) if m else None
    except OSError:
        pass
    return None


def running_workers(root="/", builds=(), runner=run):
    """Every running PHP, each traced to the build that installed it.

    A process's files are read through /proc/PID/root, so container processes
    are checked against the container's own packages. A worker whose file
    shows '(deleted)' was started before an upgrade and needs a restart.
    Returns (workers, builds found only inside containers, problems).
    """
    proc = os.path.join(root, "proc")
    if not os.path.isdir(proc):
        return [], [], ["no /proc: running PHP processes not checked"]
    problems = [] if os.geteuid() == 0 else ["not run as root: other users' PHP processes may be hidden"]
    host = os.stat(root)
    host = (host.st_dev, host.st_ino)
    by_root = {host: list(builds)}
    use_rpm = any(b["source"] == "rpm" for b in builds)
    owners, workers, extra, unreadable = {}, [], [], 0
    for pid in sorted((p for p in os.listdir(proc) if p.isdigit()), key=int):
        pid_dir = os.path.join(proc, pid)
        proot = os.path.join(pid_dir, "root")
        try:
            php = _php_path(pid_dir, os.readlink(os.path.join(pid_dir, "exe")))
            st = os.stat(proot) if php else None
        except PermissionError:
            unreadable += 1
            continue
        except OSError:  # kernel thread (no exe) or process already gone
            continue
        if not php:
            continue
        key, path = (st.st_dev, st.st_ino), php.removesuffix(" (deleted)")
        in_container = key != host
        if key not in by_root:  # rpm can't read a container's database; dpkg's is a file
            by_root[key] = from_dpkg(os_release(proot), proot)[0]
        if (key, path) not in owners:
            rpm_name = use_rpm and not in_container and _rpm_owner(runner, path)
            b = owners[key, path] = _owner(proot, path, by_root[key], rpm_name)
            if b and (in_container or b["source"] == "source"):
                extra.append({**b, "where": f"{b['where']} (pid {pid}{', container' if in_container else ''})"})
        if owners[key, path] is None:
            problems.append(f"pid {pid} runs PHP from {php}, which no checked build installed")
            continue
        workers.append({"pid": pid, "exe": php, "stale": php.endswith(" (deleted)")})
    if unreadable:
        problems.append(f"{unreadable} process(es) unreadable; run as root to check every PHP worker")
    return workers, extra, problems


def collect(root="/", runner=run):
    osr = os_release(root)
    builds, problems = [], []
    for found, issues in (from_dpkg(osr, root), from_rpm(osr, runner), from_docker(runner),
                          from_homebrew(root), from_directadmin(root)):
        builds += found
        problems += issues
    workers, extra, worker_problems = running_workers(root, builds, runner)
    problems += worker_problems
    # Same package seen through several binaries (fpm, cli) is one build;
    # the same version from Docker and Homebrew is two. Every place it was
    # seen stays listed.
    unique = {}
    for b in builds + extra:
        key = (b["source"], b["vendor"], b["stream"], b["package"], b["version"])
        if key in unique:
            unique[key] = {**unique[key], "where": f"{unique[key]['where']}, {b['where']}"}
        else:
            unique[key] = b
    if not unique:
        problems.append("no PHP build found")
    return {"os": {"id": osr[0], "stream": osr[1]}, "builds": list(unique.values()),
            "workers": workers, "problems": problems}
