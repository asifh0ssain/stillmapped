# Known issues

Low-severity findings outside [THREAT_MODEL.md](THREAT_MODEL.md), or inside it
but unable to cause a false `fixed` or a false exit 0 in any setup the reviews
could build. Each one names the review that found it.

The scanner (`stillmapped/*.py`) is frozen at commit 53605ab (2026-10-30): the
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

## stillmapped must be installed root-owned

Review 4 (out of scope). If the package itself sits in a user-writable prefix
(a user's `pip install`), that user can change its code or data, and root runs
it. Fix idea: document a root-owned install in the README.

## Crypto++ is a false match (fix after step 5)

Review 3 #9 fix. `libcrypto*.so*` also matches Crypto++'s `libcryptopp*.so*`,
which is not OpenSSL. A host using Crypto++ gets "owned by libcrypto++N, which
no record covers" (exit 2). Fix after step 5 with a narrower pattern that still
catches pip's bundled `libcrypto-<hash>.so.3`, for example the stem followed by
`-`, `.` or a digit, with a named test for each name.

## Fail-closed noise (exit 2 by design)

Known consequences of the rules, not false passes:
- Hosts running rootless Docker or Podman containers, and chrooted daemons.
- A PHP build in a user-owned or group-writable prefix (for example
  `/usr/local` as `root:staff 2775` on older Debian): its version header is
  not evidence.
- If the one `rpm -qa` file query fails, every mapped libcrypto is reported as
  "bundled copy" (the reason is wrong; the exit code is right).

## Ubuntu has no "not affected" records yet

Real-host test, 2026-11-02. On Ubuntu 24.04 the default run leaves 52 CVEs not
judged: no vendor record for ubuntu 24.04. Ubuntu's CVE tracker states "not
affected" per release, but `tools/sync` reads Ubuntu's OSV feed, which lists
fixes only. Fix idea: read the tracker's per-release status and emit
`not-affected` records, as for Debian.

## Fuzz findings that no input can reach

One-off fuzz run, 2026-11-03. Each raises an exception the scanner does not
catch (the CLI then exits 3, fail closed), but the input is written by the
kernel or by Docker, not by a user or an image author. No code change.
- F5: `from_docker`: a JSON array nested 100,000 deep in `docker image
  inspect` output raises RecursionError. Docker prints its own fixed-depth
  Config struct.
- F6: `running_workers`: a non-numeric flags field in `/proc/PID/stat` raises
  ValueError from `int()`. The kernel writes that field; the process name
  (comm), the only part a process sets, is split off before it.
- F7: `_slurp`: a NUL byte in the address field of a `/proc/PID/maps` line
  raises ValueError through `map_files/<range>`. The kernel writes that field.

## RHEL: an exact-branch and a "*" record for the same CVE, package and stream

Owner, 2026-11-03 (v0.1.5 review); corrected 2026-11-04 (security review of
0.1.5, finding 2). `_candidates` takes a record for the build's exact branch
over a `"branch": "*"` record. Both for the same CVE, package and stream is
normal, not an error: 0.1.5 held 50 such groups (plain php `*` records beside
php:X.Y module stream records), and each record covered different builds.
Since 0.1.6 only RHEL `openssl-libs` may use `*` (the validator rejects it for
anything else), and the bundled data holds no such pair.

The risk is only a pair that disagrees for the same build: a build on the
exact branch that matches both records (both origin patterns, or a record
without one) and gets a different status from each. The exact record would
win silently, as the disagreement check in `resolve_one` never sees the `*`
record. Fix idea: a load-time guard in `load_records` that rejects only such
a disagreeing pair, with a named test; a pair that agrees, or whose records
cover different builds, stays valid.

## php-cgi and lsphp: advise "restart the web server" (post-launch)

Owner, 2026-11-04 (v0.1.7 report). The text receipt advises "restart this
process (or the supervisor that runs it)" for a stale php-cgi or lsphp
process, as for any process that is neither php-fpm nor a server with libphp
loaded. The web server (or LiteSpeed) usually spawns and respawns them, so
"restart the web server" is the better advice. Output text only: no verdict
or exit code changes. Fix idea: match php-cgi and lsphp in `_advice`
(`stillmapped/cli.py`), with a named test. Post-launch.

## Ideas

- Running kernel vs vendor kernel fix per CVE (needrestart only says reboot
  needed). Validate with users first.
