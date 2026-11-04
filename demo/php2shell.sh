#!/bin/sh
# Short demo for a screen recording: PHP 8.2 on Debian 12 upgraded to the
# php2shell fix (CVE-2026-109618, CVE-2026-109619; 8.2.35-1~deb12u1, DLA-4848-1)
# while a PHP CLI worker and php-fpm keep running the old code; what Trivy and
# Grype say, and what stillmapped says.
#
#   demo/php2shell.sh
#
# Needs docker. Setup first (not for the recording): the cached scanners from
# demo/prep.sh and PHP 8.2.34-1~deb12u1 and 8.2.35-1~deb12u1 from
# demo/php2shell-prep.sh (snapshot.debian.org, verified against the signed
# InRelease and Packages files), each downloaded only if missing. Then a
# debian:12 container with 8.2.34, a CLI worker (php -r with a long sleep, as
# a queue worker) and php-fpm (master as root, workers as www-data). In a
# terminal it then waits for Enter; the visible part takes about 40 s.
#
# What this shows and what it doesn't: php8.2-fpm's postinst runs
# "invoke-rc.d php8.2-fpm restart" on upgrade. Here the image's policy-rc.d
# denies it, as in any container built from the Debian image. On a Debian 12
# host with systemd and php-fpm started by its unit, the upgrade restarts
# php-fpm. No Debian package restarts a PHP CLI worker. SYS_PTRACE lets root
# read the www-data workers' /proc/PID/maps, as in CI.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$here")
arch=$(docker version --format '{{.Server.Arch}}')
OLD=8.2.34-1~deb12u1
NEW=8.2.35-1~deb12u1
PKGS="php8.2-cli php8.2-fpm php8.2-common php8.2-opcache php8.2-readline"
CVES="CVE-2026-109618 CVE-2026-109619"
cid=

missing() { # files under demo/cache...
  for f in "$@"; do [ -e "$here/cache/$f" ] || return 0; done
  return 1
}
debs() { for p in $PKGS; do printf '%s ' "${p}_$1_$arch.deb"; done; }
setup() { # script
  mkdir -p "$here/cache" "$here/out"
  p=$(docker create -v "$here/out:/out" -v "$here/cache:/cache" debian:12 sh "/$1")
  docker cp -q "$here/$1" "$p:/$1"
  docker start -a "$p" >/dev/null
  docker rm -f "$p" >/dev/null
}

cleanup() { [ -z "$cid" ] || docker rm -f "$cid" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

echo "Setting up (not part of the recording) ..."
docker pull -q debian:12 >/dev/null
if missing "bin-$arch/trivy" "bin-$arch/grype" trivy/db ||
   [ -z "$(docker run --rm -v "$here/cache:/cache:ro" debian:12 sh -c 'ls /cache/grype 2>/dev/null')" ]; then
  setup prep.sh
fi
# shellcheck disable=SC2046
if missing php2shell-provenance.txt $(debs "$OLD") $(debs "$NEW"); then
  setup php2shell-prep.sh
fi
cid=$(docker run -d --cap-add CHECKPOINT_RESTORE --cap-add SYS_PTRACE -v "$here/cache:/cache:ro" debian:12 sleep infinity)
docker cp -q "$repo/stillmapped" "$cid:/stillmapped"
docker exec "$cid" sh -c "
  set -e
  apt-get update -qq
  cd /cache && apt-get install -y -qq --no-install-recommends procps python3 $(for p in $PKGS; do printf './%s ' "${p}_${OLD}_$arch.deb"; done) >/dev/null 2>&1
  cat > /tmp/scan.sh <<'EOS'
# Copy the package database as it is now, then run both scanners on it (read-only caches).
export TRIVY_SKIP_VERSION_CHECK=true GRYPE_DB_CACHE_DIR=/cache/grype GRYPE_DB_AUTO_UPDATE=false
export GRYPE_CHECK_FOR_APP_UPDATE=false GRYPE_DB_VALIDATE_BY_HASH_ON_START=false
rm -rf /tmp/pkgdb /tmp/scan.done && mkdir -p /tmp/pkgdb/etc /tmp/pkgdb/var/lib/dpkg
cp /etc/os-release /etc/debian_version /tmp/pkgdb/etc/ && cp /var/lib/dpkg/status /tmp/pkgdb/var/lib/dpkg/
b=/cache/bin-\$(dpkg --print-architecture)
\$b/trivy rootfs --quiet --cache-dir /cache/trivy --cache-backend memory --skip-db-update \\
  --scanners vuln --pkg-types os /tmp/pkgdb > /tmp/trivy.txt 2>&1 &
\$b/grype -q dir:/tmp/pkgdb > /tmp/grype.txt 2>&1 &
wait
touch /tmp/scan.done
EOS
  sh /tmp/scan.sh  # warm-up on the old state; it also proves both scanners report both CVEs now
  for c in $CVES; do grep -q \$c /tmp/trivy.txt && grep -q \$c /tmp/grype.txt; done
  mkdir -p /run/php && php-fpm8.2 -D"
docker exec -d "$cid" php -r 'while (true) { sleep(60); }'
sleep 2
pids=$(docker exec "$cid" sh -c 'echo $(pgrep -d, -x php),$(pgrep -d, -x php-fpm8.2)')

if [ -t 0 ]; then
  printf 'Ready. Start the recording, then press Enter. '
  read -r _
fi
clear 2>/dev/null || true

x() { docker exec "$cid" sh -c "$1"; }
step() { printf '\n== %s\n' "$1"; }
pause() { sleep 2; }

step "1. A PHP CLI worker and php-fpm are running PHP $OLD"
x "ps -o pid,user,args -p $pids | cut -c1-90; dpkg-query -W -f '\${Package} \${Version}\n' php8.2-cli php8.2-fpm"
pause

step "2. Install the fix ($NEW). No restart."
x "cd /cache && apt-get install -y --no-install-recommends $(for p in $PKGS; do printf './%s ' "${p}_${NEW}_$arch.deb"; done) 2>&1 \
   | grep -E '^Setting up php8.2-(cli|fpm)|denied' | sort -u | cut -c1-90"
docker exec -d "$cid" sh /tmp/scan.sh
pause

step "3. Trivy and Grype after the upgrade"
x "while [ ! -e /tmp/scan.done ]; do sleep 0.5; done
   for s in trivy grype; do
     for c in $CVES; do
       if grep -q \$c /tmp/\$s.txt; then
         printf '%-6s reports %s\n' \$s \$c
       else
         printf '%-6s no %s finding for php8.2 $NEW\n' \$s \$c
       fi
     done
   done"
pause

step "4. stillmapped"
x "cd / && python3 -m stillmapped $(for c in $CVES; do printf -- '--cve %s ' "$c"; done)> /tmp/sm.txt; echo \$? > /tmp/rc
   grep -E '^[0-9]+ fixed$|^\[RESTART NEEDED\]|^  - pid' /tmp/sm.txt | cut -c1-110
   rc=\$(cat /tmp/rc)
   case \$rc in 0) m='fixed';; 1) m='not fixed or restart needed';; 2) m='unknown';; *) m='error';; esac
   echo \"exit code \$rc: \$m\""
pause
