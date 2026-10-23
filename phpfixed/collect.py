"""Find PHP builds installed on this host.

Read-only. Queries the package databases (dpkg, rpm), the local Docker
daemon's image metadata, Homebrew's Cellar and DirectAdmin build dirs, and
/proc for running PHP workers. Never modifies anything, never touches the
network.
"""

import glob
import json
import os
import re
import shutil
import subprocess

RUN_TIMEOUT = 20  # seconds, per subprocess

# Binary package names that carry the PHP runtime. Extension packages
# (php8.2-mysql etc.) share the runtime's version and would only add noise.
_DEB_PKG = re.compile(r"^(?:libapache2-mod-)?(php\d+\.\d+)(?:-(?:fpm|cli|cgi|common))?$")
_RPM_BASE = re.compile(r"^(php\d?)(?:-(?:fpm|cli|common))?$")             # php, SUSE php8/php7
_RPM_SCL = re.compile(r"^(php\d\d)-php(?:-(?:fpm|cli|common))?$")          # Remi SCL
_PANEL = re.compile(r"^((?:ea|alt|plesk)-php\d\d)(?:-php)?(?:-(?:fpm|cli|common|runtime))?$")
_SURY = re.compile(r"deb\.sury\.org|\+0~\d{8}")
_PHP_V = re.compile(r"PHP\s+(\d+\.\d+\.\d+)")


def run(cmd):
    """Run a read-only command; return stdout, or None on any failure."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=RUN_TIMEOUT, check=False)
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


def _branch(version):
    """PHP branch ('8.2') from a version string, ignoring any epoch."""
    m = re.match(r"(?:\d+:)?(\d+)\.(\d+)", version)
    return f"{m.group(1)}.{m.group(2)}" if m else ""


def _build(source, vendor, stream, package, version, scheme, where):
    return {"source": source, "vendor": vendor, "stream": stream, "package": package,
            "branch": _branch(version), "version": version, "scheme": scheme, "where": where}


def from_dpkg(osr, runner=run):
    out = runner(["dpkg-query", "-W", "-f", "${Package}\t${Version}\t${db:Status-Abbrev}\n"])
    if out is None:
        return []
    builds = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 3 or not parts[2].startswith("ii"):
            continue
        name, version = parts[0], parts[1]
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
    return builds


def from_rpm(osr, runner=run):
    out = runner(["rpm", "-qa", "--qf", "%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}\n"])
    if out is None:
        return []
    builds = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        name, evr = parts
        evr = evr.replace("(none):", "")
        if _PANEL.match(name):
            pkg = _PANEL.match(name).group(1)
            vendor, stream = _panel_vendor(pkg), osr[1] or "*"
        elif _RPM_SCL.match(name):
            pkg = _RPM_SCL.match(name).group(1)
            vendor, stream = "remi", osr[1] or "*"
        elif _RPM_BASE.match(name):
            pkg = _RPM_BASE.match(name).group(1)
            vendor, stream = ("remi", osr[1]) if ".remi" in evr else osr
        else:
            continue
        builds.append(_build("rpm", vendor, stream, pkg, evr, "vercmp-rpm", name))
    return builds


def _panel_vendor(pkg):
    return {"ea": "cpanel", "alt": "cloudlinux", "plesk": "plesk"}[pkg.split("-", 1)[0]]


def from_docker(runner=run):
    """Official php:* images, read from image metadata (PHP_VERSION env)."""
    if not shutil.which("docker"):
        return []
    out = runner(["docker", "image", "ls", "--format", "{{json .}}"])
    if out is None:
        return []
    builds = []
    for line in out.splitlines():
        try:
            img = json.loads(line)
        except ValueError:
            continue
        repo = img.get("Repository", "")
        if repo not in ("php", "library/php", "docker.io/library/php"):
            continue
        env = runner(["docker", "image", "inspect", "--format", "{{json .Config.Env}}", img.get("ID", "")])
        try:
            pairs = json.loads(env or "[]")
        except ValueError:
            pairs = []
        version = next((p.split("=", 1)[1] for p in pairs if p.startswith("PHP_VERSION=")), "")
        if version:
            ref = f"{repo}:{img.get('Tag', '')}"
            builds.append(_build("docker", "docker-official", _branch(version), "php",
                                 version, "upstream", ref))
    return builds


def from_homebrew(root="/"):
    builds = []
    for cellar in ("opt/homebrew/Cellar", "usr/local/Cellar"):
        for d in sorted(glob.glob(os.path.join(root, cellar, "php*", "*"))):
            version = re.sub(r"_\d+$", "", os.path.basename(d))
            if re.match(r"\d+\.\d+\.\d+$", version):
                builds.append(_build("homebrew", "homebrew", _branch(version), "php",
                                     version, "upstream", d))
    return builds


def from_directadmin(root="/", runner=run):
    """CustomBuild compiles PHP from source into /usr/local/phpXX."""
    if not os.path.isdir(os.path.join(root, "usr/local/directadmin")):
        return []
    builds = []
    for binpath in sorted(glob.glob(os.path.join(root, "usr/local/php*/bin/php*"))):
        if not re.search(r"/bin/php\d*$", binpath) or not os.access(binpath, os.X_OK):
            continue
        m = _PHP_V.search(runner([binpath, "-v"]) or "")
        if m:
            builds.append(_build("binary", "directadmin", _branch(m.group(1)), "php",
                                 m.group(1), "upstream", binpath))
    return builds


def running_workers(root="/"):
    """PHP worker processes and the binary each one is executing.

    A worker whose binary shows '(deleted)' was started before the package
    was upgraded: the fix is installed but not running until a restart.
    """
    procs, unreadable = [], 0
    for exe_link in glob.glob(os.path.join(root, "proc/[0-9]*/exe")):
        pid = exe_link.split(os.sep)[-2]
        try:
            target = os.readlink(exe_link)
        except OSError:
            unreadable += 1
            continue
        name = os.path.basename(target.replace(" (deleted)", ""))
        if not name.startswith(("php-fpm", "php-cgi", "lsphp")):
            continue
        procs.append({"pid": pid, "exe": target, "stale": target.endswith(" (deleted)")})
    return procs, unreadable


def collect(root="/", runner=run):
    osr = os_release(root)
    builds = (from_dpkg(osr, runner) + from_rpm(osr, runner) + from_docker(runner)
              + from_homebrew(root) + from_directadmin(root, runner))
    seen, unique = set(), []
    for b in builds:
        key = (b["vendor"], b["stream"], b["package"], b["version"])
        if key not in seen:
            seen.add(key)
            unique.append(b)
    workers, unreadable = running_workers(root)
    return {"os": {"id": osr[0], "stream": osr[1]}, "builds": unique,
            "workers": workers, "workers_unreadable": unreadable}
