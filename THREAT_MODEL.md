# Threat model

The scanner answers one question: is the code running in memory on this host
fixed for CVE X? The asset is that answer. The worst failure is a false
`fixed` or a false exit 0. Reviews test against this page only. Findings
outside it go to [ISSUES.md](ISSUES.md).

## Who can act

| Actor | Status | What it means |
|---|---|---|
| Root on the host | Out of scope | Root can change the files, the package databases and the kernel's view. Nothing a scanner on the same host reads can be proven against root. |
| Root inside a container | Documented trust limit | Root in a rootful container can edit that container's package database. Verdicts for its processes say `container package database`. The scanner must not let that container affect verdicts for the host or other containers, and must not hang or crash on its files. |
| Any non-root local user | **In scope** | Must never cause a false `fixed` or a false exit 0, for any process or build. A user may cause `unknown`, a problem (exit 2) or `restart-needed` (exit 1): those are fail-closed answers. |

Non-root users include users in their own user namespace (`unshare -U`,
rootless Docker or Podman). Their processes are untraced (exit 2), because
they can write the package database those processes would be judged by.

## Evidence rule

`fixed` needs evidence from root-owned sources only. If any file or directory
in a chain is not owned by root, is group- or world-writable, or is reached
through a symlink, the result is unknown. Package databases (dpkg, rpm) and
`/proc` are root-owned by design. A version read from a path a user can write
(a Homebrew Cellar, a user-owned install prefix) is not evidence.

## Trust in package databases and image metadata

stillmapped trusts root-installed package databases and official-image
metadata like other scanners. It does not verify package or image
authenticity: a package or image built by an attacker, installed by root,
carries whatever version it claims. That is root acting (out of scope), and
it is covered by package signature checks and image signing, not by this
tool. Every result names its evidence in a `trust` field: `host-pkgdb`,
`container-pkgdb`, `image-metadata` or `root-owned-source`.

## Inputs and how they are treated

- `/proc`: written by the kernel, but process names, paths and file contents
  are chosen by users. Each process is pinned by an open `/proc/PID` fd.
- Package databases: trusted for the host; trusted per container under the
  limit above. The installed file must match the package database (dpkg
  `md5sums`, `rpm -V`), which checks consistency, not tampering by root.
- Files under any root: read with symlinks resolved inside that root, without
  blocking, regular files only, at most 64 MiB, never past their size.
- Bundled records (`stillmapped/data/`): project data, validated on load. A bad
  record stops the run (exit 3).

## Not covered

- OpenSSL linked statically into a program.
- Version strings as the package manager records them: a repository that
  copies a vendor's exact version format can't be told apart.
- A compromised kernel.
- Denial of service that ends in a fail-closed answer (exit 1 or 2), or a slow
  scan: tracked in ISSUES.md, not a false pass. Scan-wide limits (65,536
  processes, 262,144 matching maps lines, 1,000 problems) end the scan with one
  problem (exit 2).
