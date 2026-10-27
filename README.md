# phpfixed

Is the PHP on this host fixed for a given CVE? Read-only, offline, no dependencies.

`php -v` can't answer that: distros backport fixes without changing the PHP
version, and third-party rebuilds can carry a higher version without the fix.
phpfixed finds every PHP build on the host, matches each against verified
vendor fix records bundled with the tool, and never calls a build fixed on a guess.

## What it checks

- dpkg (Debian, Ubuntu, Sury) and rpm (RHEL family, SUSE, Remi) packages
- cPanel `ea-php`, CloudLinux `alt-php`, Plesk `plesk-php`
- Docker images carrying `PHP_VERSION` (official `php` images and images built from them)
- Homebrew `php` / `php@X.Y`, DirectAdmin CustomBuild `/usr/local/phpXX`
- Running php-fpm, php-cgi, lsphp and Apache mod_php: still running a pre-upgrade binary?

## Usage

    python3 -m phpfixed                        # every bundled CVE
    python3 -m phpfixed --cve CVE-2026-109618  # one CVE
    python3 -m phpfixed --json

Run as root to see every running process.

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

## Install

Python 3.9+, no dependencies. Copy the `phpfixed/` directory to the host and run
`python3 -m phpfixed` next to it, or `pip install .` for a `phpfixed` command.

## When to use something else

phpfixed answers one question, fast, for the PHP advisories it bundles. For
everything else on a host, use the vendor's own tooling (`pro fix` on Ubuntu,
`dnf updateinfo --cve`, `zypper lp --cve`, debsecan) or a general scanner such
as Vuls or Trivy. Its niche is hosts those miss or misread: control-panel PHP
(cPanel, CloudLinux, Plesk, DirectAdmin), mixed sources on one host, and
workers still running a pre-upgrade binary.

## Known gaps

Each one fails closed (`unknown` or exit 2), never `fixed`.

- AlmaLinux, Rocky and openSUSE Leap have no records of their own yet.
- LiteSpeed `lsphp` packages are not collected.
- A custom Docker image with apt-installed PHP and no `PHP_VERSION` is not detected.
- DirectAdmin's header path is unverified on a real DirectAdmin host.

## Data

`phpfixed/data/*.json`: one file per advisory, listing its CVEs and one record
per vendor build:

```json
{
  "vendor": "debian", "stream": "12", "package": "php8.2", "branch": "8.2",
  "status": "fixed", "match": "vercmp-deb", "fixed": "8.2.35-1~deb12u1",
  "origin": "deb\\d+u\\d+",
  "evidence_url": "https://security-tracker.debian.org/tracker/CVE-2026-109618",
  "checked": "2026-10-22"
}
```

`status` is `fixed`, `not-fixed`, or `unknown` with a `note`. `origin` is a
pattern the installed version must contain to be called fixed, so a rebuild
with a higher version isn't mistaken for the vendor's patched one. Every record
is validated on load and an invalid one stops the run. To add a record, cite
the vendor's own advisory page in `evidence_url`; a PR without one is closed.

## How it's tested

- Unit tests, one named regression test per defect found in audit, on Python 3.9 to 3.14.
- CI installs each distro's own PHP in Debian, Ubuntu, AlmaLinux and openSUSE
  containers and runs phpfixed against it. On distros with records, every
  build must get a verdict.
- Version ordering is diffed against the real `dpkg --compare-versions` and
  rpm's `rpmvercmp` on random version pairs every run.
