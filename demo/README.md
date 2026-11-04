# Live demo

One command:

    demo/run.sh

It shows what package scanners report when the code in memory is not the code
on disk. Results go to `demo/out/<UTC time>/`: one file per command, and
`summary.txt` with the key lines. A run takes about 5 minutes.

## Needs

- Docker, and nothing else on the host. Downloads are public: the `debian:12`
  and `almalinux:9` images, Debian snapshot packages, pinned Trivy and Grype
  releases with their current databases, and cPanel's public EA4 repository.
- On macOS with Docker Desktop, `docker pull` fails with
  `docker-credential-desktop: executable file not found in $PATH` when the
  shell does not have Docker Desktop's helper directory on PATH. Run:

      PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH" demo/run.sh

## What it runs

| Script | Container | Does |
|---|---|---|
| `prep.sh` | debian:12 | Downloads OpenSSL 3.0.14-1~deb12u1 (vulnerable to CVE-2024-6119) and 3.0.14-1~deb12u2 (fixed). Checks each `.deb` against the SHA256 in the gpgv-verified InRelease and Packages files of the same snapshot. Downloads Trivy and Grype by pinned SHA256, then their databases. |
| `deb.sh stale` | debian:12 | Installs the vulnerable version, starts `openssl s_server`, upgrades without a restart, scans before and after. Records `/proc/PID/maps`, library hashes, needrestart output and the needrestart source lines it decides from. Runs stillmapped with the demo-only record `openssl-demo.json`; `check.py` requires exit 1 and "in-memory version unknown, restart needed" for the server's libcrypto. |
| `deb.sh thirdparty` | debian:12 | Rebuilds the vulnerable packages as version `3.0.14-1+thirdparty1`, installs them, scans. Runs stillmapped; `check.py` requires exit 2, `unknown`, and no `fixed` verdict. |
| `eaphp.sh` | almalinux:9 (amd64) | Installs the oldest `ea-php82-php-cli` that EA4 serves, records its rpm changelog, scans, searches the Grype database for CVE-2026-109618, runs the current stillmapped. stillmapped must answer `unknown` with exit 2. |

## Short demos for a screen recording

Not part of `run.sh`. Each sets up first, waits for Enter in a terminal, then
runs four steps: the running process, the upgrade with no restart, Trivy and
Grype, stillmapped.

- `video.sh`: OpenSSL 3.0.14-1~deb12u1 to deb12u2 under a running `openssl s_server` (CVE-2024-6119), about 40 s.
- `php2shell.sh`: php8.2 8.2.34-1~deb12u1 to 8.2.35-1~deb12u1 (CVE-2026-109618, CVE-2026-109619) under a PHP CLI worker and php-fpm, about 15 s; `php2shell-prep.sh` downloads and verifies the debs as `prep.sh` does. It also adds `SYS_PTRACE`, so root can read the www-data php-fpm workers' maps.

Limit of `php2shell.sh`: the container's `policy-rc.d` denies the restart
that php8.2-fpm's postinst asks for. On a Debian 12 host with systemd,
php-fpm under its unit is restarted by the upgrade. The queue worker case
holds everywhere.

## Isolation

No `--privileged`, no host network. One added capability,
`CHECKPOINT_RESTORE`, lets stillmapped read `/proc/PID/map_files` inside the
containers; on a host it runs as root and needs none. The only host mounts are
`demo/out` and `demo/cache`. The cache is read-only in the three test containers. `prep.sh`
mounts it read-write because it fills it. Scripts and the `stillmapped/` package
go in with `docker cp`. Scans run with database updates off.

## Platform of the quoted run

The run quoted in the top-level README was on arm64, with the ea-php
container under amd64 emulation, so the Debian file paths show `aarch64`.

## Not pinned

The Trivy and Grype databases change daily. Each run records the version and
build date it used in `summary.txt`. The `debian:12` and `almalinux:9` tags
move; each run records the image digests.
