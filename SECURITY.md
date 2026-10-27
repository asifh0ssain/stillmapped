# Security

phpfixed is meant to run as root on production hosts, so every input (package
databases, /proc, image metadata, file paths) is treated as hostile.

## Guarantees under test

- Read-only: writes nothing, changes nothing.
- No network. Docker is queried only over the local unix socket.
- Executes only `rpm` and `docker`, from a fixed PATH (`/usr/bin:/bin` when root),
  with a two-variable environment. Never executes a binary it finds on disk.
- Never reports `fixed` on ambiguous data; see the README.

A way to break any of these is a vulnerability. So is any input that makes
phpfixed report `fixed` for a build that is not.

## Reporting

Use GitHub's private vulnerability reporting ("Report a vulnerability" on the
Security tab). Please do not open a public issue. Expect a reply within 7 days.
