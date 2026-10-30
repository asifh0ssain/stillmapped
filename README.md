# stillmapped

Is the code that runs in memory on this host fixed for CVE X? Read-only,
offline, no dependencies. Modules: PHP, and OpenSSL (`libcrypto.so.3`).

Package scanners answer from the package database. That is not the same
question. A process that started before an upgrade still runs the old code,
and a third-party rebuild can carry a higher version without the fix. `php -v`
can't answer either: distros backport fixes without changing the version.
stillmapped finds every build on the host and every running process that maps
one, matches each against verified vendor fix records bundled with the tool,
and never calls a build fixed on a guess.

## Principles

1. **Running code is the truth.** The verdict is about what is mapped into
   memory, not what the package database says is installed.
2. **Unknown is an answer.** When the tool can't prove a fix, it says
   `unknown` and exits 2. It never turns an ambiguous case into `fixed` or
   exit 0. A library it can't trace to its package is a problem, never fixed.
3. **Every verdict has a receipt.** Package, version, the vendor's evidence
   URL, the date the record was checked, the PID, and the mapped file path.
   Plain JSON.

## What the demo shows

`demo/run.sh` runs these cases in Docker and saves every command's output
([demo/README.md](demo/README.md)). Quotes below are from run
20261030T222606Z on an amd64 server (docker 29.1.3, linux/amd64; all 4 checks
PASS, 548 s), with Trivy 0.76.1 and Grype 0.121.0.

**OpenSSL upgraded, process not restarted** (Debian 12, CVE-2024-6119, fixed
in `3.0.14-1~deb12u2`). Before the upgrade, both scanners report it:

    libssl3   3.0.14-1~deb12u1   3.0.14-1~deb12u2   deb   CVE-2024-6119   High

After the upgrade, neither has a CVE-2024-6119 row. The running server still
maps the old library:

    libssl3:amd64	3.0.14-1~deb12u2
        755 Fri Oct 30 22:29:45 2026 openssl s_server -www -key k -cert c -accept 4433
    ... 00:30 801915   /usr/lib/x86_64-linux-gnu/libcrypto.so.3 (deleted)
    ... 00:30 801916   /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)

The same PID and inodes appear before the upgrade, without `(deleted)`, next
to `libssl3 3.0.14-1~deb12u1`. `libcrypto.so.3` on disk now has the SHA256 of
the fixed package (`4d13ab2d…`); the vulnerable package's file has `bd58dc2f…`.
`python3 -m stillmapped --cve CVE-2024-6119 --json` exited 1 for the server
(stale-stillmapped.txt, lines 74-79):

      "status": "restart-needed",
      "reason": "in-memory version unknown, restart needed",
        "pid": "755",
        "path": "/usr/lib/x86_64-linux-gnu/libcrypto.so.3 (deleted)",

**Third-party rebuild.** The vulnerable package, rebuilt as
`3.0.14-1+thirdparty1`:

    dpkg: 3.0.14-1+thirdparty1 > 3.0.14-1~deb12u2
    bd58dc2f…  /usr/lib/x86_64-linux-gnu/libcrypto.so.3
    bd58dc2f…  /tmp/official-old/usr/lib/x86_64-linux-gnu/libcrypto.so.3   (3.0.14-1~deb12u1)
    4d13ab2d…  /tmp/official-new/usr/lib/x86_64-linux-gnu/libcrypto.so.3   (3.0.14-1~deb12u2)

Trivy and Grype reported no CVE-2024-6119 row. stillmapped exited 2
(thirdparty-stillmapped.txt, lines 74-75):

      "status": "unknown",
      "reason": "3.0.14-1+thirdparty1 doesn't look like a debian build; can't confirm it carries the fix",

**cPanel ea-php** (AlmaLinux 9, cPanel's public EA4 repository).
cPanel's changelog puts the CVE-2026-109618 fix in 8.2.35. The installed CLI
is 8.2.34. Trivy and Grype reported no rows. stillmapped reported unknown.

    $ rpm -qf /opt/cpanel/ea-php82/root/usr/bin/php
    ea-php82-php-cli-8.2.34-1.1.1.cpanel.x86_64

    $ rpm -q --changelog ea-php82-php-cli ea-php82-runtime   (eaphp-changelog.txt, lines 87-88)
    * Tue Oct 20 2026 ... - 8.2.35-1
    - EA-13610: Update ea-php82 from v8.2.34 to v8.2.35 (CVE-2026-109618, CVE-2026-109619)

That entry is in the `ea-php82-runtime` changelog. The `ea-php82-php-cli`
changelog ends at `8.2.34-1` and names neither CVE. `grype db search --vuln
CVE-2026-109618` lists RHEL 9 `php` (`< 0:8.2.35-1.module+el9.8.0+25111+a1450321`)
and `cpe:2.3:a:php:php` (`>= 7.3.0, < 8.2.35 || ...`), and no ea-php entry.
stillmapped has no cPanel record and exited 2 (eaphp-stillmapped.txt, lines 27-28):

      "status": "unknown",
      "reason": "no verified record for cpanel 9 ea-php82 (PHP 8.2); check the vendor's advisory"

In the first case, the scanners' answer changed when the package changed; the
code in memory did not. In the second, the version changed and the code did not.

**A `(deleted)` mapping is not proof of old code.** `libssl.so.3` also showed
`(deleted)` above, but it has the same SHA256 in the vulnerable and the fixed
package (`4d351715…`). The fix is in `libcrypto.so.3`. A verdict must come
from the file that carries the fix.

## What it checks

- dpkg (Debian, Ubuntu, Sury) and rpm (RHEL family, SUSE, Remi) packages
- cPanel `ea-php`, CloudLinux `alt-php`, Plesk `plesk-php`
- Docker images built from the official `php` image
- DirectAdmin CustomBuild `/usr/local/phpXX`, when its version header is
  root-owned all the way down. Homebrew is not read: its Cellar is user-owned,
  so its version is not evidence; a running Homebrew PHP is reported untraced.
- Every running PHP (php-fpm, php-cgi, lsphp, CLI daemons, Apache or NGINX Unit
  with a PHP module), traced to the package or source build that installed it,
  inside containers too. PHP that no checked build installed is reported, and so
  is PHP still running a pre-upgrade binary.

## Usage

    python3 -m stillmapped                        # every bundled CVE
    python3 -m stillmapped --cve CVE-2026-109618  # one CVE
    python3 -m stillmapped --all                  # also list fixed results
    python3 -m stillmapped --json                 # every result, always

The text output lists not-fixed, unknown and restart-needed results, then one
line with the number of fixed results. Run as root to see every running process.

| Exit | Meaning |
|---|---|
| 0 | every build fixed, every part of the host checked |
| 1 | a build is not fixed, or a worker needs a restart |
| 2 | a build is unknown, or part of the host couldn't be checked |
| 3 | error, or no bundled data for a requested CVE |

## Guarantees

- Changes nothing. Executes only `rpm` and `docker` (pinned to the local socket),
  from a fixed PATH (`/usr/bin:/bin` when root) with a minimal environment.
  Never executes a binary found on disk.
- No network.
- Ambiguity resolves to `unknown`: no record, conflicting records, pre-release
  versions, a version not matching the vendor's own pattern, invalid data.
- `fixed` needs evidence from root-owned sources only: a version read from a
  file or directory that is not root-owned, is group- or world-writable, or is
  reached through a symlink counts as unknown. See
  [THREAT_MODEL.md](THREAT_MODEL.md): no non-root local user may cause a false
  `fixed` or a false exit 0.
- Exit 0 needs every build found fixed and every running PHP traced to a
  checked build. Run as non-root, it can't be 0. Without `--cve`, a module with
  no build on the host (for example no PHP) is an `[INFO]` line, "no PHP build
  found"; if no module is found at all, that is a problem (exit 2). With
  `--cve`, a module of the named CVEs with no build is a problem (exit 2).
  PHP that no package owns is seen only while running as php, php-fpm,
  php-cgi, lsphp or frankenphp, or with libphp loaded. A source build that is
  not running, or a renamed binary, is not seen. A `[SCOPE]` line and the
  `limits` field say so.
- For OpenSSL, every mapped file whose name matches `libcrypto*.so*` is
  checked, whatever its path (Crypto++'s `libcryptopp` matches too, and is
  reported as owned by a package no record covers). A copy no package owns (for example one bundled in a Python
  wheel) is reported with its path as "bundled copy, not owned by a package"
  (exit 2). OpenSSL linked statically into a program is not seen, and exit 0
  says nothing about it. Text and JSON output state this in a `[SCOPE]` line
  and the `limits` field.
- A package's verdict applies to a mapped file only if the installed file is
  the package's own copy: for dpkg, not diverted and equal to the package's
  `md5sums` entry; for rpm, it passes `rpm -V`. Otherwise the file is
  untraced (exit 2).
- A running process whose mapped library or PHP binary differs from the
  installed file is reported as "in-memory version unknown, restart needed"
  (exit 1), never as fixed.
- A dpkg package in any state other than `install ok installed` or
  `hold ok installed` (half-installed, unpacked, half-configured, ...) is
  reported as a problem (exit 2), on the host and inside containers.
- If the host's packages change while the scan runs, the result is a problem
  (exit 2): run it again.
- Files under a container's root are read with symlinks resolved inside that
  root, never blocking on a FIFO or device and never reading past a file's size.

## Install

Python 3.9+, no dependencies. stillmapped runs as root, so it must be installed
root-owned: its directory and every directory above it owned by root and not
group- or world-writable. A copy that a user can write lets that user change
what root runs and what it reports.

Install the release file. Download `stillmapped` and `stillmapped.sha256`
from the project's GitHub Releases page into one directory, then, as root:

    sha256sum -c stillmapped.sha256
    install -o root -g root -m 0755 stillmapped /usr/local/bin/stillmapped

`stillmapped` is a single-file Python zipapp. To build the same file from
source, run `ci/zipapp.sh`: it writes `dist/stillmapped` and
`dist/stillmapped.sha256`, and the same tree gives the same hash.

Or, as root, copy the `stillmapped/` directory to a root-owned location (for
example `/usr/local/lib/stillmapped`) and run `python3 -m stillmapped` from
there. Do not use a user's `pip install --user` or a virtualenv a user owns.

## When to use something else

stillmapped answers one question, fast, for the advisories it bundles. For
everything else on a host, use the vendor's own tooling (`pro fix` on Ubuntu,
`dnf updateinfo --cve`, `zypper lp --cve`, debsecan) or a general scanner such
as Vuls, Trivy or Grype. Its scope: control-panel PHP (cPanel, CloudLinux,
Plesk, DirectAdmin), mixed sources on one host, and workers still running a
pre-upgrade binary.

To find processes that need a restart, use needrestart; it does not map
processes to CVEs or check fixed versions.

## Known gaps

Each one fails closed (`unknown` or exit 2), never `fixed`.

- AlmaLinux, Rocky and openSUSE Leap have no records of their own yet.
- LiteSpeed `lsphp` packages are not collected.
- Docker images whose PHP comes from a distro package are checked only while running.
- Running PHP inside an RPM-based container is reported as unchecked.
- Processes in another user namespace (rootless Docker or Podman, `unshare -U`)
  are untraced, because a plain user can write their package database. A host
  running rootless Docker or Podman containers reports exit 2.
- A chrooted process (postfix `chroot=y`, sshd privilege separation) is
  reported as "chrooted process" (exit 2).
- DirectAdmin's header path is unverified on a real DirectAdmin host.

Trust limits. These can give a wrong `fixed`:

- Inside a container, verdicts use the container's own package database, which
  root in that container can edit. Each verdict names the database it used
  (`host` or `container`).
- The `md5sums` and `rpm -V` checks test consistency with the package
  database, not tampering by root: root can change both the file and the
  database.
- Version strings are trusted as the package manager records them. A repository
  that copies a vendor's exact version format can't be told apart.
- OpenSSL linked statically into a program is not seen.

## Status

Bundled data: 155 CVEs (66 PHP, 89 OpenSSL), 1094 records, one file per
CVE. `tools/sync` generated it from the vendor feeds snapshot of 2026-10-30
(`20261030T231616Z`); every record comes from one primary vendor feed.

| Distro | Records |
|---|---|
| Debian 12 / 13 | 116 / 102 |
| Ubuntu 22.04 / 24.04 / 26.04 / 26.10 | 110 / 86 / 64 / 2 |
| RHEL 9 | 177 |
| SLES 15 SP4 / SP5 / SP6 / SP7 | 16 / 26 / 45 / 130 |
| php.net upstream | 220 |

glibc and libxml2 come after OpenSSL passes CI.

## Data

`stillmapped/data/*.json`: one file per CVE (the format also allows one file
per advisory, listing several CVEs), with one record per vendor build:

```json
{
  "vendor": "debian", "stream": "12", "package": "php8.2", "branch": "8.2",
  "status": "fixed", "match": "vercmp-deb", "fixed": "8.2.35-1~deb12u1",
  "origin": "^8\\.2\\.\\d+-\\d+~deb12u\\d+$",
  "evidence_url": "https://security-tracker.debian.org/tracker/CVE-2026-109618",
  "checked": "2026-10-22"
}
```

`status` is `fixed`, `not-fixed`, or `unknown` with a `note`. `origin` is the
vendor's exact version format, anchored with `^` and `$` and without `|`, which the installed version
must match to be called fixed. Distros backport fixes onto old upstream
versions, so without it a third-party rebuild with a higher version (or an
epoch) would compare as newer and pass. Every record
is validated on load and an invalid one stops the run. To add a record, cite
the vendor's own advisory page in `evidence_url`; a PR without one is closed.

## How it's tested

- Unit tests, with a named regression test for every defect found in seven
  reviews. They are run locally; the latest run was on Python 3.12.
- CI has never run. The workflow (`.github/workflows/ci.yml`) is written: it
  runs the unit tests on Python 3.9 to 3.14, installs each distro's own PHP in
  Debian, Ubuntu, AlmaLinux and openSUSE containers, and diffs version ordering
  against the real `dpkg --compare-versions` and rpm's `rpmvercmp`.
- `demo/run.sh` runs the live cases above in Docker. The latest run (above)
  was on amd64; all 4 checks passed.
