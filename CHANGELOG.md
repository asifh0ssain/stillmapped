# Changelog

## 0.1.0

First public release.

- Collectors: dpkg (read from the status database), rpm, cPanel / CloudLinux /
  Plesk, Docker images, Homebrew, DirectAdmin (version read from the installed
  header, never executed), running workers including Apache mod_php.
- Fails closed: unreadable sources, unowned workers and running PHP with no
  installed build are reported and give exit 2.
- Data: one file per advisory, every record validated on load; an invalid
  record stops the run. Conflicting records resolve to unknown.
- Version ordering follows dpkg's verrevcmp and rpm's rpmvercmp, checked
  against the real tools in CI.
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
