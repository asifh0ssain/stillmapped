# Changelog

## 0.1.6 (2026-11-04)

Fixes from the security review of 0.1.5 (two findings, both outside
THREAT_MODEL.md; neither lets a non-root user cause a false `fixed` or a false
exit 0).

- Finding 1: a `"branch": "*"` record no longer judges RHEL php. In 0.1.5 a
  plain RHEL php record covered every branch, so a plain-format build on
  another branch (for example `8.3.19-1.el9`) read `fixed` for CVE-2023-0567
  by the 8.0 fix, and `not-affected` for CVE-2024-11236. Such builds now read
  `unknown`.
  - Scanner: the validator rejects `"branch": "*"` for anything but RHEL
    `openssl-libs`, which Red Hat rebased within RHEL 9, for every status.
  - Data: the 50 plain RHEL php records (35 fixed, 15 not affected) are on
    branch `8.0` again; no other field changed. Regenerated offline from the
    same snapshot `20261103T175904Z` (manifest SHA-256
    `aaf51644bc663fbbed8865263faf86222f573c678f7914703b1207e045621a68`):
    161 CVEs, 1280 records (1123 fixed, 103 not affected, 54 not fixed).
  - Unchanged: plain RHEL php 8.0 builds, php module stream builds and every
    RHEL `openssl-libs` build read as in 0.1.5, including across rebases.
  - Named tests for each, in the scanner and generator suites.
- Finding 2: the ISSUES.md entry on an exact-branch and a `*` record for one
  RHEL CVE, package and stream is corrected. Such pairs are normal (0.1.5 held
  50); a guard must reject only a pair that disagrees for the same build.
- Docs: the `resolve.py` docstring, its branch comment and the README's
  Red Hat paragraph state the `openssl-libs` exception.

## 0.1.5 (2026-11-03)

Data fixes from the deep verification round (differential test against Trivy
and Grype, second-source audit, mutation testing).

- Bundled data regenerated from snapshot `20261103T175904Z` (manifest SHA-256
  `aaf51644bc663fbbed8865263faf86222f573c678f7914703b1207e045621a68`):
  161 CVEs, 1280 records (1123 fixed, 103 not affected, 54 not fixed). Against
  0.1.4: 173 records added, 101 RHEL records re-keyed to one record per
  release (same fix), 74 Debian records changed (24 fixed versions moved to
  the release's own build, 49 origins also admit the release's plain build);
  no fixed or not-affected record became not fixed, and none was lost.
- RHEL: a plain package (`openssl-libs`) is judged per RHEL release, not per
  upstream branch, as Red Hat compares one package version line across
  rebases: a fully patched RHEL 9.8 host (`1:3.5.8-2.el9_8`) no longer reads
  unknown for fixes made on the 3.0 or 3.2 branch. Scanner: a RHEL record may
  have `"branch": "*"`, and a record for the exact branch wins over it.
- Debian: a fix made before the release shipped is fixed in the release's own
  first build (for example 3.5.1-1 for trixie), so trixie's release build no
  longer reads not fixed or unknown. A fix made after the release keeps the
  lowest later `~debNuM` build.
- Vendor "affected, no fix" gives `not-fixed` records: Red Hat "Affected" /
  "Fix deferred" for `openssl-libs`, and Debian "vulnerable" with no fixed
  version for the release. Ubuntu fixes that no USN carries come from
  Canonical's CVE record when it states the same released version. The Ubuntu
  libcrypto binary is now the release's own (`libssl3t64` from 24.04).
- Tests: named tests for the seven surviving mutants M1 to M7 (each now
  killed; none showed a code defect). The test suite now keeps its fixture
  directories in one per-run directory and removes it at exit.
- Generator budget raised to 550 logic lines (owner, 2026-11-03).

## 0.1.4 (2026-11-03)

Fixes from an independent review with OpenAI Codex Security (four findings,
triaged by the maintainer). The scanner budget is raised to 850 logic lines.

- Every result carries a `trust` field naming its evidence: `host-pkgdb`,
  `container-pkgdb`, `image-metadata` or `root-owned-source`, in `--json` and
  in the text receipt. README and THREAT_MODEL state that stillmapped trusts
  root-installed package databases and official-image metadata like other
  scanners, and does not verify package authenticity (finding 1: no
  verification feature).
- `--strict`: a CVE not judged for a build (no vendor record for its release)
  makes the result not fully checked (exit 2). The default is unchanged. The
  README states exactly what exit 0 means (finding 2).
- A process in its own mount namespace under the host's root (a bind mount)
  is judged by the host's dpkg version only if its file and `/var/lib/dpkg/status`
  are the ones the version was read from, as rpm already required; otherwise
  it is untraced (exit 2). Older code with matching older dpkg metadata bound
  over the packaged path was reported fixed (finding 3).
- Scan-wide limits: 65,536 processes, 262,144 matching maps lines and 1,000
  distinct problems. Past any of them, one problem and exit 2. Problems,
  workers and mappings are no longer copied as cumulative lists (finding 4).
- Hardening: each process root is read through its pinned `/proc/PID`
  directory handle, and its start time is checked again at the end; a change
  is a problem.

## 0.1.3 (2026-11-03)

- fuzz hardening: container file lists can no longer stop or stall a host
  scan. Found by a one-off stdlib fuzz run (9 parsers, 10 minutes each).
  - A NUL byte in a path in a dpkg `.list` file made `os.readlink` raise
    ValueError and stopped the whole scan (exit 3). That path is now
    untraced.
  - Symlink resolution inside a process root (`_in_root`) rebuilt the path
    string for every component, so one deep path in a `.list` file took
    quadratic time (100,000 components: 14 s; a 64 MiB list: hours). It is
    now linear: the 50,000-component case takes under 0.1 s.
  - `validate_record` never raises: a field of the wrong type, or an origin
    pattern that fails to compile for any reason (RecursionError too), is a
    problem. Not-affected records get the same origin and type checks as
    fixed records. A fixed version with an empty release (ending in `-`) is
    rejected, because rpm orders `1` before `1-`.

## 0.1.2 (2026-11-02)

- docker: one image without Env no longer hides all images, found on a real
  host. `opensuse/leap:15.6` has no `Config.Env`, so `docker image inspect`
  with the `{{json .Config.Env}}` template failed for the whole batch and
  every image was reported unchecked (exit 2). The scanner now reads
  `{{json .Config}}`; if the batch still fails, each image is inspected on its
  own and only an image that fails is reported unchecked.

## 0.1.1 (2026-11-02)

Data refresh. The scanner code does not change.

- Bundled data regenerated by `tools/sync/refresh.sh` from a new snapshot:
  161 CVEs, 1208 records (1094 fixed, 80 not affected, 34 not
  fixed, 0 unknown).
  - Snapshot: `20261102T224118Z`
  - Manifest SHA-256: `de0c5811c8091d55ddfca909489001e877cc84b743904b255ae5788f4eea26a7`
- Against the previous release: 0 CVEs added, 0 removed; 0 records
  added, 0 changed, 0 removed. Fixed records that became
  not fixed or unknown: 0; fixed records removed: 0.
- Per distro (records added / changed / removed):
  - none

## 0.1.0 (2026-11-02)

First public release. CI is green on this tree (run #4, commit dce2c73):
unit tests on Python 3.9 to 3.14 and the smoke test on Debian 12 and 13,
Ubuntu 22.04, 24.04 and 26.04, AlmaLinux 9 and openSUSE Leap 15.6.

- Renamed from phpfixed to stillmapped.
- Bundled data is generated by `tools/sync` from five primary vendor feeds:
  161 CVEs (PHP and OpenSSL), 1208 records (1094 fixed, 80 not affected, 34
  not fixed), one file per CVE.
  - Snapshot: `20261030T231616Z`
  - Manifest SHA-256: `0d63c04bab0c397e60d65831d7af0b50f78f075f9c45a7e3c9cc434394c0e72d`
- New record status `not-affected`, from the vendor's own statement (Debian
  tracker; Red Hat VEX where a php:X.Y module stream names the branch). It
  counts like fixed for the exit code and is shown as "not affected". Red Hat
  "known affected" for a named module stream gives a `not-fixed` record. SUSE
  and Red Hat statements that name no branch give no record.
- Default run (no `--cve`): a CVE with no record for a build's vendor and
  release is not judged; an `[INFO]` line gives the count and the JSON
  `not_judged` field lists them. No effect on the exit code. With `--cve`,
  unchanged.
- The "no verified record" reason names the module (OpenSSL, not PHP).
- Debian origins accept both release markers, `[~+]debNuM` (point updates
  use `~`, security updates `+`), so a fix in a `+deb13u1` build no longer
  rejects the release's own later `~deb13u3` build (CI run #3).
- The hand-checked records (`php2shell.json`) moved to
  `tools/sync/hand/` as the generator's oracle.
- Release workflow: a `v*` tag runs the unit tests, builds the zipapp and
  publishes `stillmapped` and `stillmapped.sha256` as a GitHub Release.

- Collectors: dpkg (read from the status database), rpm, cPanel / CloudLinux /
  Plesk, Docker images, Homebrew, DirectAdmin (version read from the installed
  header, never executed), running workers including Apache mod_php.
- Fails closed: unreadable sources, unowned workers and running PHP with no
  installed build are reported and give exit 2.
- Data: one file per advisory, every record validated on load; an invalid
  record stops the run. Conflicting records resolve to unknown.
- Version ordering follows dpkg's verrevcmp and rpm's rpmvercmp.
- Run as root, commands are found in `/usr/bin:/bin` only.
- Every running PHP is traced to the package (dpkg file lists, `rpm -qf`) or
  root-owned source build that installed it, reading containers through
  `/proc/PID/root`. Untraced PHP is a problem; it never counts as stale.
- Distro records need an anchored `origin`; PPA-style rebuilds and epochs no
  longer pass as the vendor's fix.
- Docker images count only when built from the official `php` image.
- No PHP found, or not running as root, is a problem (exit 2).
- SUSE `httpd-prefork` + `mod_php8`, NGINX Unit, FrankenPHP and PHP CLI daemons
  are recognized.
- JSON output: `{host, cves, results, stale_workers, problems}`.
