#!/bin/sh
# Short demo for a screen recording: old OpenSSL code still mapped after an
# upgrade, what Trivy and Grype say, and what stillmapped says.
#
#   demo/video.sh
#
# Needs docker. Setup first (not for the recording): the cached packages and
# scanners from demo/run.sh (downloaded and verified by demo/prep.sh if any is
# missing), then a debian:12 container set up as demo/deb.sh does: the
# vulnerable libssl3 3.0.14-1~deb12u1 and a running openssl s_server. In a
# terminal it then waits for Enter; the visible part takes about 40 s.
# Trivy and Grype read Debian packages from the package database and
# /etc/os-release only, so step 2 copies those (after the upgrade) and starts
# both scans at once; Grype spends about 35 s loading its database.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$here")
arch=$(docker version --format '{{.Server.Arch}}')
OLD=3.0.14-1~deb12u1
NEW=3.0.14-1~deb12u2
cid=

need() {
  for f in "libssl3_${OLD}_$arch.deb" "openssl_${OLD}_$arch.deb" "libssl3_${NEW}_$arch.deb" \
           "openssl_${NEW}_$arch.deb" "bin-$arch/trivy" "bin-$arch/grype" trivy/db; do
    [ -e "$here/cache/$f" ] || return 0
  done
  [ -n "$(docker run --rm -v "$here/cache:/cache:ro" debian:12 sh -c 'ls /cache/grype 2>/dev/null')" ] || return 0
  return 1
}

cleanup() { [ -z "$cid" ] || docker rm -f "$cid" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

echo "Setting up (not part of the recording) ..."
docker pull -q debian:12 >/dev/null
if need; then
  mkdir -p "$here/cache" "$here/out"
  p=$(docker create -v "$here/out:/out" -v "$here/cache:/cache" debian:12 sh /prep.sh)
  docker cp -q "$here/prep.sh" "$p:/prep.sh"
  docker start -a "$p" >/dev/null
  docker rm -f "$p" >/dev/null
fi
cid=$(docker run -d --cap-add CHECKPOINT_RESTORE -v "$here/cache:/cache:ro" debian:12 sleep infinity)
docker cp -q "$repo/stillmapped" "$cid:/stillmapped"
docker exec "$cid" sh -c "
  set -e
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends procps python3 >/dev/null
  dpkg -i /cache/libssl3_${OLD}_$arch.deb /cache/openssl_${OLD}_$arch.deb >/dev/null
  cd /tmp && openssl req -x509 -newkey rsa:2048 -nodes -keyout k -out c -subj /CN=demo -days 1 2>/dev/null
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
  sh /tmp/scan.sh  # warm-up on the old state; it also proves both scanners report the CVE now
  grep -q CVE-2024-6119 /tmp/trivy.txt && grep -q CVE-2024-6119 /tmp/grype.txt"
docker exec -d "$cid" sh -c 'cd /tmp && exec openssl s_server -www -key k -cert c -accept 4433 >/dev/null 2>&1'
sleep 2
pid=$(docker exec "$cid" pgrep -x openssl)

if [ -t 0 ]; then
  printf 'Ready. Start the recording, then press Enter. '
  read -r _
fi
clear 2>/dev/null || true

x() { docker exec "$cid" sh -c "$1"; }
step() { printf '\n== %s\n' "$1"; }
pause() { sleep 2; }

step "1. A process is running with OpenSSL $OLD"
x "ps -o pid,args -p $pid | cut -c1-90; dpkg-query -W -f '\${Package} \${Version}\n' libssl3"
pause

step "2. Install the fix ($NEW). No restart."
x "apt-get install -y /cache/libssl3_${NEW}_$arch.deb /cache/openssl_${NEW}_$arch.deb 2>/dev/null \
   | grep '^Setting up libssl3' | cut -c1-90"
docker exec -d "$cid" sh /tmp/scan.sh
pause

step "3. Trivy and Grype after the upgrade"
x "while [ ! -e /tmp/scan.done ]; do sleep 0.5; done
   for s in trivy grype; do
     if grep -q CVE-2024-6119 /tmp/\$s.txt; then
       printf '%-6s reports CVE-2024-6119\n' \$s
     else
       printf '%-6s no CVE-2024-6119 finding for libssl3 $NEW\n' \$s
     fi
   done"
pause

step "4. stillmapped"
x "cd / && python3 -m stillmapped --cve CVE-2024-6119 > /tmp/sm.txt; echo \$? > /tmp/rc
   awk '/^\[RESTART-NEEDED\]/ {on=1} on && /^$/ {exit} on' /tmp/sm.txt | cut -c1-90
   rc=\$(cat /tmp/rc)
   case \$rc in 0) m='fixed';; 1) m='not fixed or restart needed';; 2) m='unknown';; *) m='error';; esac
   echo \"exit code \$rc: \$m\""
pause
