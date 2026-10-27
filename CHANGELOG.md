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
- JSON output: `{host, cves, results, stale_workers, problems}`.
