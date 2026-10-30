"""Find PHP builds installed on this host.

Read-only. Reads dpkg's status database, queries rpm and the local Docker
daemon's image metadata, and reads Homebrew's Cellar, DirectAdmin's installed
headers and /proc for running PHP workers. Never modifies anything, never
touches the network, never executes a binary found on disk.

Every collector returns (builds, problems). A problem is anything that kept
a part of the host from being checked; it makes the overall result unknown.
"""

import glob
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess

from .vercmp import branch

RUN_TIMEOUT = 20  # seconds, per subprocess
MAX_READ = 64 << 20  # bytes hashed per mapped file at most
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
# A file that is PHP itself. A package counts as a PHP build only if it
# installs one: cPanel's ea-phpXX-runtime shares the build's name but not its code.
_PHP_FILE = re.compile(r"/(?:s?bin|cgi-bin)/(?:php-fpm|php-cgi|lsphp|php)[\d.]*$|/(?:libphp|mod_php)[^/]*\.so$")


def _which(name):
    return shutil.which(name, path=_PATH)


def run(cmd, ok=(0,)):
    """Run a read-only command with a minimal environment; stdout, or None
    unless it exited with a code in ok."""
    exe = _which(cmd[0])
    if not exe:
        return None
    try:
        p = subprocess.run([exe, *cmd[1:]], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", stdin=subprocess.DEVNULL,
                           env={"PATH": _PATH, "LC_ALL": "C"}, timeout=RUN_TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return p.stdout if p.returncode in ok else None


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


def _build(source, vendor, stream, package, version, scheme, where, module="php"):
    return {"source": source, "vendor": vendor, "stream": stream, "package": package,
            "branch": branch(version), "version": version, "scheme": scheme, "where": where,
            "module": module, "db": "host"}


def _upstream(source, version, where):
    """A build compiled from php.net source; judged by the upstream release."""
    return _build(source, "upstream", "*", "php", version, "upstream", where)


def from_dpkg(osr, root="/", libs={}):
    """Installed PHP packages, and the library packages named in libs
    ({package: module}), read straight from dpkg's status database."""
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
        if name in libs:
            builds.append(_build("dpkg", *osr, name, version, "vercmp-deb", name, libs[name]))
            continue
        m = _DEB_PKG.match(name) or _PANEL.match(name)
        if not m or not any(_PHP_FILE.search(f) for f in _dpkg_list(root, name)):
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


def from_rpm(osr, runner=run, libs={}):
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
        if name in libs:
            builds.append(_build("rpm", *osr, name, evr, "vercmp-rpm", name, libs[name]))
            continue
        if m := _PANEL.match(name):
            vendor, stream = _panel_vendor(m.group(1)), osr[1] or "*"
        elif m := _RPM_SCL.match(name):
            vendor, stream = "remi", osr[1] or "*"
        elif m := _RPM_BASE.match(name):
            vendor, stream = ("remi", osr[1]) if ".remi" in evr else osr
        else:
            continue
        builds.append(_build("rpm", vendor, stream, m.group(1), evr, "vercmp-rpm", name))
    names = [b["where"] for b in builds if b["module"] == "php"]
    if names:  # each matched an anchored pattern above, so none starts with '-'
        # %{=NAME} repeats the name per file; plain %{NAME} makes rpm print nothing.
        out = runner(["rpm", "-q", "--qf", "[%{=NAME}\t%{FILENAMES}\n]", *names])
        if not out:
            return [b for b in builds if b["module"] != "php"], ["rpm file lists couldn't be read; PHP packages not checked"]
        php = {n for n, _, f in (line.partition("\t") for line in out.splitlines()) if _PHP_FILE.search(f)}
        builds = [b for b in builds if b["module"] != "php" or b["where"] in php]
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


def _php_path(exe, maps):
    """The PHP file a process runs ('(deleted)' kept): its own binary, or a
    PHP module mapped into Apache or Unit. None if it runs no PHP."""
    name = os.path.basename(exe.removesuffix(" (deleted)"))
    if _PHP_EXE.match(name):
        return exe
    if _EMBEDS.match(name):
        return next((m[5] for m in maps if _PHP_MODULE.search(m[5])), None)
    return None


def _lib_file(path, files):
    """The record file (a soname) whose library a mapped path is, or None.
    Any copy counts: libcrypto.so.3.5.8, a bundled libcrypto-1a2b3c4d.so.3,
    /memfd:libcrypto.so.3; libcryptopp.so does not."""
    name = os.path.basename(path.removesuffix(" (deleted)"))
    return next((f for f in files if re.search(rf"{re.escape(f.split('.so')[0])}(-[^/]*)?\.so(\.|$)", name)), None)


def _read(d, name):
    """A /proc/PID file, read through the pinned directory fd d."""
    with open(os.open(name, os.O_RDONLY, dir_fd=d), encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _sha256(fd, algo="sha256"):
    with open(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_READ:
            raise OSError("not a regular file of at most 64 MiB")
        h = hashlib.new(algo)
        while chunk := fh.read(1 << 20):
            h.update(chunk)
        return h.hexdigest()


def _same_code(d, line, proot, path):
    """Does a mapping (a split /proc/PID/maps line) hold the file installed
    at path? (True, {}) by device and inode, or by equal SHA-256 of the
    mapped object (/proc/PID/map_files) and the installed file; False when
    they differ or the installed file is gone; None when it can't tell."""
    try:
        st = os.stat(os.path.join(proot, path.lstrip("/")))
    except FileNotFoundError:
        return False, {"why": "installed file is gone"}
    except OSError as e:
        return None, {"why": e.strerror}
    if f"{os.major(st.st_dev):02x}:{os.minor(st.st_dev):02x}" == line[3] and str(st.st_ino) == line[4]:
        return True, {}
    rng = "-".join(a.lstrip("0") or "0" for a in line[0].split("-"))  # map_files drops zero padding
    try:
        mapped = _sha256(os.open(f"map_files/{rng}", os.O_RDONLY, dir_fd=d))
        installed = _sha256(os.open(os.path.join(proot, path.lstrip("/")), os.O_RDONLY))
    except OSError as e:
        return None, {"why": f"can't read the mapped file: {e.strerror or e}"}
    return mapped == installed, {"mapped_sha256": mapped, "installed_sha256": installed}


def _root_owned(path):
    st = os.stat(path)
    return st.st_uid == 0 and not st.st_mode & 0o022


def _dpkg_list(root, pkg, ext="list"):
    """Lines of dpkg's file list (or md5sums) for a package, any architecture."""
    info, files = os.path.join(root, "var/lib/dpkg/info"), []
    for lst in [os.path.join(info, f"{pkg}.{ext}"), *glob.glob(os.path.join(info, f"{glob.escape(pkg)}:*.{ext}"))]:
        try:
            with open(lst, encoding="utf-8", errors="replace") as fh:
                files += fh.read().splitlines()
        except OSError:
            continue
    return files


def _in_root(proot, path):
    """path with each symlink resolved inside proot, as the process sees it
    (/lib -> usr/lib on merged-/usr systems). None on a symlink loop."""
    parts, done, hops = path.split("/"), "", 0
    while parts:
        part = parts.pop(0)
        if part == "..":
            done = done.rsplit("/", 1)[0]  # never above the process root
        elif part not in ("", "."):
            try:
                target = os.readlink(os.path.join(proot, f"{done}/{part}".lstrip("/")))
            except OSError:  # not a symlink
                done = f"{done}/{part}"
                continue
            hops += 1
            if hops > 40:
                return None
            parts = target.split("/") + parts
            done = "" if target.startswith("/") else done
    return done or "/"


def _dpkg_owns(proot, pkg, path):
    """The entry in pkg's file list that is path, or None."""
    name = os.path.basename(path)
    return next((f for f in _dpkg_list(proot, pkg)
                 if f == path or os.path.basename(f) == name and _in_root(proot, f) == path), None)


def _tampered(proot, b, path, runner):
    """Why the installed file at path is not the package's own copy, or None.
    Checks consistency with the package database, not tampering by root."""
    if b["source"] == "rpm":  # rpm -V exits 1 when a file differs or the package is gone
        out = runner(["rpm", "-V", "--noconfig", b["where"]], ok=(0, 1))
        bad = out is None or "is not installed" in out or any(
            line.endswith(" " + path) and ("5" in line[:9] or "S" in line[:9] or line.startswith("missing"))
            for line in out.splitlines())
        return "it fails rpm -V" if bad else None
    if b["source"] != "dpkg":
        return None
    entry = _dpkg_owns(proot, b["where"], path)
    try:
        with open(os.path.join(proot, "var/lib/dpkg/diversions"), encoding="utf-8", errors="replace") as fh:
            diverted = fh.read().split("\n")[0::3]  # lines: original, diverted to, package
    except FileNotFoundError:
        diverted = []
    if entry in diverted:
        return "it is diverted (dpkg-divert)"
    try:
        sums = {p: h for h, _, p in (line.partition("  ") for line in _dpkg_list(proot, b["where"], "md5sums"))}
        if entry.lstrip("/") not in sums:
            return "dpkg has no md5sum for it"
        if _sha256(os.open(os.path.join(proot, path.lstrip("/")), os.O_RDONLY), "md5") != sums[entry.lstrip("/")]:
            return "it differs from dpkg's md5sum"
    except OSError as e:
        return f"it can't be checked ({e.strerror or e})"
    return None


def _dpkg_owner(proot, path):
    """Any dpkg package that lists path, or None."""
    names = (os.path.basename(f)[:-5] for f in glob.glob(os.path.join(proot, "var/lib/dpkg/info/*.list")))
    return next((p for p in names if _dpkg_owns(proot, p, path)), None)


def _rpm_owner(runner, path):
    """Name of the rpm package that owns path, or None."""
    out = runner(["rpm", "-qf", "--qf", "%{NAME}\n", path])
    return out.strip() if out and len(out.split()) == 1 else None


def _owner(proot, path, builds, rpm_name, module="php"):
    """The build of module that installed the file at path, as seen from
    proot: a package that lists it, or (PHP only) a source build whose prefix
    holds it and whose root-owned header gives its version. None if nothing
    checked does."""
    prefix = os.path.dirname(os.path.dirname(path))
    for b in builds:
        if b["module"] == module and (module == "php" and b["where"] == prefix
                                      or b["source"] == "rpm" and b["where"] == rpm_name
                                      or b["source"] == "dpkg" and _dpkg_owns(proot, b["where"], path)):
            return b
    if module != "php":
        return None
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


def running_workers(root="/", builds=(), runner=run, libs={}, files={}):
    """Every running PHP, and every mapping of a library file named in
    files, each traced to the package or build that installed it.

    Each process is pinned by an open /proc/PID directory fd and must still
    be alive after all its reads, so a reused PID can't mix in another
    process. Its files are read through /proc/PID/root, so container
    processes are checked against the container's own packages. Code still
    mapped that differs from the installed file needs a restart.
    Returns (workers, builds found only inside containers, problems, mappings).
    """
    proc = os.path.join(root, "proc")
    if not os.path.isdir(proc):
        return [], [], ["no /proc: running processes not checked"], []
    problems = [] if os.geteuid() == 0 else ["not run as root: other users' processes may be hidden"]
    host = os.stat(root)
    host = (host.st_dev, host.st_ino)
    by_root = {host: list(builds)}
    use_rpm = any(b["source"] == "rpm" for b in builds)
    owners, workers, mappings, extra, unreadable = {}, [], [], [], 0
    for pid in sorted((p for p in os.listdir(proc) if p.isdigit()), key=int):
        proot = os.path.join(proc, pid, "root")
        try:
            d = os.open(os.path.join(proc, pid), os.O_RDONLY | os.O_DIRECTORY)
        except OSError:
            continue
        pw, pm, notes = [], [], []  # committed only if the process is still alive at the end
        try:
            start = _read(d, "stat").rsplit(")", 1)[1].split()[19]
            exe = os.readlink("exe", dir_fd=d)
            maps = [m for m in (line.split(None, 5) for line in _read(d, "maps").splitlines())
                    if len(m) == 6 and m[5].startswith("/")]
            php = _php_path(exe, maps)
            subjects = {m[5]: m for m in maps if _lib_file(m[5], files)}  # one per file
            if php:
                subjects[php] = next((m for m in maps if m[5] == php), None)
            st = os.stat(proot) if subjects else None
            for mapped, line in subjects.items():
                key, path = (st.st_dev, st.st_ino), mapped.removesuffix(" (deleted)")
                in_container = key != host
                module = "php" if mapped == php else files[_lib_file(path, files)]
                if key not in by_root:  # rpm can't read a container's database; dpkg's is a file
                    by_root[key] = [{**b, "db": "container"} for b in
                                    from_dpkg(os_release(proot), proot, libs)[0]]
                if (key, path, module) not in owners:
                    rpm_name = use_rpm and not in_container and _rpm_owner(runner, path)
                    b = _owner(proot, path, by_root[key], rpm_name, module)
                    why = b and _tampered(proot, b, path, runner) or b
                    if b is None and module != "php":
                        other = rpm_name or _dpkg_owner(proot, path)
                        why = f"owned by {other}, which no record covers" if other else "bundled copy, not owned by a package"
                    owners[key, path, module] = why
                    if isinstance(why, dict) and (in_container or b["source"] == "source"):
                        extra.append({**b, "where": f"{b['where']} (pid {pid}{', container' if in_container else ''})"})
                b = owners[key, path, module]
                if not isinstance(b, dict):  # None (no owner) or why its file isn't the package's
                    notes.append(f"pid {pid} runs {mapped}, which no checked package or build installed"
                                 + (f": {b}" if b else ""))
                    continue
                same, info = _same_code(d, line, proot, path) if line else (None, {"why": "not in maps"})
                if same is None:
                    notes.append(f"pid {pid}: can't compare {mapped} with the installed file ({info['why']})")
                elif mapped == php:
                    pw.append({"pid": pid, "exe": php, "stale": not same, **info})
                else:
                    pm.append({"pid": pid, "start": start, "path": mapped, "file": _lib_file(path, files),
                               "dev": line[3], "inode": line[4], "same": same, "build": b, **info})
            _read(d, "stat")  # the pinned fd fails (ESRCH) if the process has exited
        except PermissionError:
            unreadable += 1
            continue
        except (OSError, IndexError):  # kernel thread (no exe) or process gone
            continue
        finally:
            os.close(d)
        problems, workers, mappings = problems + notes, workers + pw, mappings + pm
    if unreadable:
        problems.append(f"{unreadable} process(es) unreadable; run as root to check every process")
    return workers, extra, problems, mappings


def collect(root="/", runner=run, libs={}, files={}):
    """libs and files: {package: module} and {soname: module} from the
    library records."""
    osr = os_release(root)
    builds, problems = [], []
    for found, issues in (from_dpkg(osr, root, libs), from_rpm(osr, runner, libs), from_docker(runner),
                          from_homebrew(root), from_directadmin(root)):
        builds += found
        problems += issues
    workers, extra, worker_problems, mappings = running_workers(root, builds, runner, libs, files)
    problems += worker_problems
    # Same package seen through several binaries (fpm, cli) is one build;
    # the same version from Docker and Homebrew is two. Every place it was
    # seen stays listed.
    unique = {}
    for b in builds + extra:
        key = (b["source"], b["vendor"], b["stream"], b["package"], b["version"], b["db"])
        if key in unique:
            unique[key] = {**unique[key], "where": f"{unique[key]['where']}, {b['where']}"}
        else:
            unique[key] = b
    return {"os": {"id": osr[0], "stream": osr[1]}, "builds": list(unique.values()),
            "workers": workers, "mappings": mappings, "problems": problems}
