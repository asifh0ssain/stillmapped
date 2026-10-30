# Known issues

Low-severity findings outside [THREAT_MODEL.md](THREAT_MODEL.md), or inside it
but unable to cause a false `fixed` or a false exit 0 in any setup the reviews
could build. Each one names the review that found it.

The scanner (`phpfixed/*.py`) is frozen at commit 53605ab (2026-10-30): the
fourth independent review, scoped to THREAT_MODEL.md, found no way for a
non-root local user to cause a false `fixed` or a false exit 0. Changes after
this point need a new threat-model review.

## rpm -V lines are matched by the mapped path only

Review 3, #7 (suspected, not reproduced). `rpm -qf` resolves symlinked
directories, so a package whose database path runs through a symlinked
directory could report a changed file under its database path. That line
would not end with the mapped path, and the change would be missed. No
bundled distro package installs libraries through a symlinked directory.
Fix idea: treat any `S`, `5`, `?` or `missing` line for the package as a
failure, or map database paths through the process root before comparing.

## Single read without a short-read check

Review 3, #8 (suspected, not reproduced). `_slurp` reads a file with one
`os.read` of its size. On FUSE or NFS a short read could hash only a common
prefix of two files. Fix idea: read until the size is reached and fail on a
short read.

## Docker group is trusted like root

Review 4 (out of scope). Images found through the local Docker daemon can
contribute `fixed` verdicts. Access to the daemon socket is root-equivalent,
so this is not a non-root vector; a user without access gets a problem
(exit 2). The socket is pinned to `/var/run/docker.sock`, so a rootless daemon
is not queried. Fix idea: state the Docker-group assumption in the threat model.

## phpfixed must be installed root-owned

Review 4 (out of scope). If the package itself sits in a user-writable prefix
(a user's `pip install`), that user can change its code or data, and root runs
it. Fix idea: document a root-owned install in the README.

## Fail-closed noise (exit 2 by design)

Known consequences of the rules, not false passes:
- Hosts running rootless Docker or Podman containers, and chrooted daemons.
- Crypto++ (`libcryptopp*.so*` matches `libcrypto*.so*`): reported as owned by
  a package no record covers.
- A PHP build in a user-owned or group-writable prefix (for example
  `/usr/local` as `root:staff 2775` on older Debian): its version header is
  not evidence.
- If the one `rpm -qa` file query fails, every mapped libcrypto is reported as
  "bundled copy" (the reason is wrong; the exit code is right).
