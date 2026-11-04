#!/bin/sh
# Runs in debian:12 with demo/cache writable (called by demo/php2shell.sh).
# Downloads PHP 8.2 for bookworm from snapshot.debian.org and verifies it as
# demo/prep.sh does for OpenSSL: 8.2.34-1~deb12u1, the last build before
# Debian's fix for CVE-2026-109618 and CVE-2026-109619 (php2shell), and
# 8.2.35-1~deb12u1, the fix (DLA-4848-1). Both from bookworm-security.
set -eu
apt-get update -qq
apt-get install -y -qq --no-install-recommends curl ca-certificates xz-utils >/dev/null

get() { # url sha-command hash file
  [ -f "/cache/$4" ] || curl -fsSL -o "/cache/$4.part" "$1"
  [ -f "/cache/$4" ] || mv "/cache/$4.part" "/cache/$4"
  echo "$3  /cache/$4" | $2 -c --quiet
}

# By SHA1, as snapshot.debian.org names its files.
while read -r sha f; do
  get "https://snapshot.debian.org/file/$sha" sha1sum "$sha" "$f"
done <<'EOF'
f2f8edde1a55e26599c101cc9e1e8b9c143263fe php8.2-cli_8.2.34-1~deb12u1_amd64.deb
b07a6a19996c604b70320648eb960e7d4581e02c php8.2-cli_8.2.34-1~deb12u1_arm64.deb
461cc520e515af200f9d5f3fc145e7e9a0ce0298 php8.2-fpm_8.2.34-1~deb12u1_amd64.deb
5ed06ee63df582ccb88b84bb4625bc41a708f579 php8.2-fpm_8.2.34-1~deb12u1_arm64.deb
d2c0afef66fffa29f6ce43c6570872f671a1b106 php8.2-common_8.2.34-1~deb12u1_amd64.deb
08c7bbdacc2b4cf6ccd388b07bbb066730c1fc31 php8.2-common_8.2.34-1~deb12u1_arm64.deb
e4585bf2e5fc65f16100297d5151150766ec15fc php8.2-opcache_8.2.34-1~deb12u1_amd64.deb
0d8a7358849f1a39cadcdb3cbcf19f6738cafeab php8.2-opcache_8.2.34-1~deb12u1_arm64.deb
babdc6b3187b4bb4308f280d14bdbb822110c2a6 php8.2-readline_8.2.34-1~deb12u1_amd64.deb
788258117b4f7866f45a829eea0b91d28bf04265 php8.2-readline_8.2.34-1~deb12u1_arm64.deb
0e3e99188ac27b40de75be872af7966a8328fd90 php8.2-cli_8.2.35-1~deb12u1_amd64.deb
998f2549ad5c4112e75e4862e7b19c753c30eaab php8.2-cli_8.2.35-1~deb12u1_arm64.deb
9c5e052da14c70ac867b8128389a482c8a7600d7 php8.2-fpm_8.2.35-1~deb12u1_amd64.deb
b23a685ec5d4a33b15fb03a433255900b6253208 php8.2-fpm_8.2.35-1~deb12u1_arm64.deb
b445e13507eced20e781f5bac5c40be461893836 php8.2-common_8.2.35-1~deb12u1_amd64.deb
0da769889519c6fe77d317424bb6743e898facf6 php8.2-common_8.2.35-1~deb12u1_arm64.deb
1c00ea0e356d7eaa04ad65fcfb7935ca8db6b92e php8.2-opcache_8.2.35-1~deb12u1_amd64.deb
f0e34d81b9572b0fcb658cd6676991110c76ca44 php8.2-opcache_8.2.35-1~deb12u1_arm64.deb
d596d23ae1be93b47bfb2a4f293e5315931c3f77 php8.2-readline_8.2.35-1~deb12u1_amd64.deb
5bce4a0d4a31733626953842f4fdf7b014904578 php8.2-readline_8.2.35-1~deb12u1_arm64.deb
EOF

# Then by SHA256 from the Packages index of bookworm-security at the snapshot
# that first published each version, with that index checked against the
# InRelease file verified by gpgv against the Debian archive keyring.
log=/cache/php2shell-provenance.txt
: > "$log.part"
while read -r stamp ver; do
  base=https://snapshot.debian.org/archive/debian-security/$stamp/dists/bookworm-security
  curl -fsSL -o /tmp/InRelease "$base/InRelease"
  echo "== debian-security $stamp bookworm-security" >> "$log.part"
  gpgv --keyring /usr/share/keyrings/debian-archive-keyring.gpg --output /tmp/Release \
    /tmp/InRelease >> "$log.part" 2>&1
  for arch in amd64 arm64; do
    idx=main/binary-$arch/Packages.xz
    want=$(awk -v f="$idx" '/^SHA256:/ {s=1; next} /^[^ ]/ {s=0} s && $3 == f {print $1}' /tmp/Release)
    curl -fsSL -o /tmp/Packages.xz "$base/$idx"
    echo "$want  /tmp/Packages.xz" | sha256sum -c --quiet
    xz -dc /tmp/Packages.xz > /tmp/Packages
    for p in php8.2-cli php8.2-fpm php8.2-common php8.2-opcache php8.2-readline; do
      f=${p}_${ver}_$arch.deb
      sha=$(awk -v p="$p" -v v="$ver" 'BEGIN {RS = ""}
        index($0, "Package: " p "\n") == 1 && index($0, "\nVersion: " v "\n") {
          match($0, /\nSHA256: [0-9a-f]+/); print substr($0, RSTART + 9, 64)}' /tmp/Packages)
      [ -n "$sha" ] || { echo "FAIL $f not listed in bookworm-security" >> "$log.part"; exit 1; }
      echo "$sha  /cache/$f" | sha256sum -c --quiet
      echo "OK $f sha256 $sha" >> "$log.part"
    done
  done
done <<'EOF'
20261004T220601Z 8.2.34-1~deb12u1
20261021T160509Z 8.2.35-1~deb12u1
EOF
mv "$log.part" "$log"
