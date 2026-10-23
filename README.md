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
  from a fixed PATH with a minimal environment. Never executes a binary found on disk.
- No network.
- Ambiguity resolves to `unknown`: no record, conflicting records, pre-release
  versions, a version not matching the vendor's own pattern, invalid data.

## Data

`phpfixed/data/*.json`: one file per advisory. Every record names the vendor,
OS stream, package, PHP branch, fixed version and the vendor page it was checked
against. An invalid record stops the run.
