#!/bin/sh
# Runs in debian:12 with demo/cache writable. Downloads and verifies
# everything the scenario containers need, so they run without curl (which
# would pull in a current libssl3) and with a read-only cache.
set -eu
TRIVY=0.76.1
GRYPE=0.121.0
apt-get update -qq
apt-get install -y -qq --no-install-recommends curl ca-certificates xz-utils >/dev/null

get() { # url sha-command hash file
  [ -f "/cache/$4" ] || curl -fsSL -o "/cache/$4.part" "$1"
  [ -f "/cache/$4" ] || mv "/cache/$4.part" "/cache/$4"
  echo "$3  /cache/$4" | $2 -c --quiet
}

# OpenSSL from snapshot.debian.org, by SHA1. deb12u1 is vulnerable to
# CVE-2024-6119; deb12u2 (DSA-5764-1) is the fix.
while read -r sha f; do
  get "https://snapshot.debian.org/file/$sha" sha1sum "$sha" "$f"
done <<'EOF'
c3412f42361e96b5d035dbadb58cbb774a0fd9aa libssl3_3.0.14-1~deb12u1_amd64.deb
d00557c46aae839937b769140b1af9b7fc6813f7 libssl3_3.0.14-1~deb12u1_arm64.deb
4da2388c574a9dbb9bfef32240d405bc33c28fe7 openssl_3.0.14-1~deb12u1_amd64.deb
17a1c520d059092820d37462e2e9363e43e32f1c openssl_3.0.14-1~deb12u1_arm64.deb
68b793c03778544fc4e4deef71508cd78e5bb5db libssl3_3.0.14-1~deb12u2_amd64.deb
642d1293b39735feb4cfe6ac5dd48117622192a4 libssl3_3.0.14-1~deb12u2_arm64.deb
d775d73211dce35e81c27e671e5981f87b039487 openssl_3.0.14-1~deb12u2_amd64.deb
e3816bc304a2045a6b9f441c32888240f36cf67d openssl_3.0.14-1~deb12u2_arm64.deb
EOF

# Then by SHA256 from the Packages index of the suite that published each
# version, at the same snapshot time, with that index checked against the
# InRelease file verified by gpgv against the Debian archive keyring.
log=/out/provenance.txt
: > "$log"
while read -r archive stamp suite ver; do
  base=https://snapshot.debian.org/archive/$archive/$stamp/dists/$suite
  curl -fsSL -o /tmp/InRelease "$base/InRelease"
  echo "== $archive $stamp $suite" >> "$log"
  gpgv --keyring /usr/share/keyrings/debian-archive-keyring.gpg --output /tmp/Release \
    /tmp/InRelease >> "$log" 2>&1
  for arch in amd64 arm64; do
    idx=main/binary-$arch/Packages.xz
    want=$(awk -v f="$idx" '/^SHA256:/ {s=1; next} /^[^ ]/ {s=0} s && $3 == f {print $1}' /tmp/Release)
    curl -fsSL -o /tmp/Packages.xz "$base/$idx"
    echo "$want  /tmp/Packages.xz" | sha256sum -c --quiet
    xz -dc /tmp/Packages.xz > /tmp/Packages
    for p in libssl3 openssl; do
      f=${p}_${ver}_$arch.deb
      sha=$(awk -v p="$p" -v v="$ver" 'BEGIN {RS = ""}
        index($0, "Package: " p "\n") == 1 && index($0, "\nVersion: " v "\n") {
          match($0, /\nSHA256: [0-9a-f]+/); print substr($0, RSTART + 9, 64)}' /tmp/Packages)
      [ -n "$sha" ] || { echo "FAIL $f not listed in $suite" >> "$log"; exit 1; }
      echo "$sha  /cache/$f" | sha256sum -c --quiet
      echo "OK $f sha256 $sha" >> "$log"
    done
  done
done <<'EOF'
debian 20240822T210525Z bookworm-proposed-updates 3.0.14-1~deb12u1
debian-security 20240903T185433Z bookworm-security 3.0.14-1~deb12u2
EOF

# Scanners from their GitHub releases, by SHA256 from the release checksums.
while read -r arch sha f; do
  get "https://github.com/aquasecurity/trivy/releases/download/v$TRIVY/$f" sha256sum "$sha" "$f"
  mkdir -p "/cache/bin-$arch"
  tar -xzf "/cache/$f" -C "/cache/bin-$arch" trivy
done <<EOF
amd64 c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0 trivy_${TRIVY}_Linux-64bit.tar.gz
arm64 e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f trivy_${TRIVY}_Linux-ARM64.tar.gz
EOF
while read -r arch sha f; do
  get "https://github.com/anchore/grype/releases/download/v$GRYPE/$f" sha256sum "$sha" "$f"
  tar -xzf "/cache/$f" -C "/cache/bin-$arch" grype
done <<EOF
amd64 64e07133d3486115de647a66581461dccf5c732748a0a3119077395565f15519 grype_${GRYPE}_linux_amd64.tar.gz
arm64 86f570f75ca947ea3dd6486309232bcff6d78e44ba081ae75ab14eab72be3dae grype_${GRYPE}_linux_arm64.tar.gz
EOF

# Databases: not pinned (the vendors don't keep old builds), so fetched fresh
# once per run and recorded. Every scenario scans with this same copy.
bin=/cache/bin-$(dpkg --print-architecture)
rm -rf /cache/trivy /cache/grype
"$bin/trivy" image --download-db-only --cache-dir /cache/trivy --quiet
GRYPE_DB_CACHE_DIR=/cache/grype "$bin/grype" db update -q
{
  echo "== scanner versions and databases used by every verdict below"
  "$bin/trivy" --version --cache-dir /cache/trivy
  "$bin/grype" version
  GRYPE_DB_CACHE_DIR=/cache/grype "$bin/grype" db status
} >> /out/versions.txt 2>&1
