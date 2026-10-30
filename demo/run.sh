#!/usr/bin/env bash
# Live demo: what package scanners report when old code is still mapped.
#
#   demo/run.sh
#
# Needs only docker. Downloads public images, Debian snapshot packages,
# pinned Trivy and Grype releases with their databases, and cPanel's public
# EA4 repository. Containers run on the default bridge network with one added
# capability, CHECKPOINT_RESTORE, so phpfixed can read /proc/PID/map_files.
# The only host mounts are demo/out (results) and demo/cache (read-only,
# except for the download step that fills it). Scripts and the phpfixed
# package are copied in with docker cp.
# Output: demo/out/<UTC time>/, one file per command, plus summary.txt.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$here")
out="$here/out/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$out" "$here/cache"
native=linux/$(docker version --format '{{.Server.Arch}}')

docker pull -q --platform "$native" debian:12 >/dev/null
docker pull -q --platform linux/amd64 almalinux:9 >/dev/null
{
  docker version --format 'docker server {{.Server.Version}} ({{.Server.Os}}/{{.Server.Arch}})'
  docker image inspect --format '{{index .RepoDigests 0}}' debian:12 almalinux:9
} > "$out/versions.txt"

container() { # cache-mode platform image script args...
  local mode=$1 platform=$2 image=$3 cid rc=0
  shift 3
  cid=$(docker create --platform "$platform" --cap-add CHECKPOINT_RESTORE \
    -v "$out:/out" -v "$here/cache:/cache:$mode" \
    "$image" sh "/$@")
  for f in prep.sh scan.sh deb.sh eaphp.sh check.py openssl-demo.json; do docker cp -q "$here/$f" "$cid:/$f"; done
  docker cp -q "$repo/phpfixed" "$cid:/phpfixed"
  docker start -a "$cid" || rc=$?
  docker rm -f "$cid" >/dev/null
  [ "$rc" = 0 ] || echo "container $image $* exited $rc" | tee -a "$out/errors.txt"
}

echo "== download and verify"
container rw "$native" debian:12 prep.sh
for mode in stale thirdparty; do
  echo "== debian:12 $mode"
  container ro "$native" debian:12 deb.sh "$mode"
done
echo "== almalinux:9 + cPanel ea-php (amd64, emulated on arm64 hosts)"
container ro linux/amd64 almalinux:9 eaphp.sh

cd "$out"
{
  cat versions.txt provenance.txt errors.txt 2>/dev/null || true
  for f in *-maps-*.txt *-hashes.txt stale-needrestart*.txt stale-needrestart-source.txt thirdparty-package.txt eaphp-package.txt eaphp-php-owner.txt eaphp-runtime-files.txt eaphp-changelog-check.txt eaphp-grype-db-search.txt eaphp-phpfixed.txt; do
    printf '\n### %s\n' "$f"; cat "$f" 2>/dev/null || echo "(missing)"
  done
  for f in stale-phpfixed.txt thirdparty-phpfixed.txt; do
    printf '\n### %s (CHECK line)\n' "$f"; grep '^CHECK' "$f" 2>/dev/null || echo "(missing)"
  done
  for f in *-trivy-*.txt *-grype-*.txt; do
    printf '\n### %s (CVE-2024-6119, ea-php and php rows)\n' "$f"
    head -n 1 "$f"
    grep -iE 'CVE-2024-6119|ea-php|[[:space:]]php' "$f" || echo "(no matching row)"
  done
} > summary.txt
echo "done: $out/summary.txt"
