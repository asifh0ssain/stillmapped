#!/bin/sh
# Runs in debian:12. MODE is one of:
#   stale       vulnerable OpenSSL, start a process that maps it, upgrade to
#               the fixed package, do not restart, scan.
#   thirdparty  the vulnerable libssl3, rebuilt by a "third party" with the
#               vendor's package name and a higher version, scan.
# The CVE-2024-6119 fix is in libcrypto.so.3 (X.509 name checks); libssl.so.3
# is byte-identical in both versions. Hashes below show which code is which.
set -eu
MODE=$1
mkdir -p /phpfixed/data && cp /openssl-demo.json /phpfixed/data/
ARCH=$(dpkg --print-architecture)
OLD=3.0.14-1~deb12u1
NEW=3.0.14-1~deb12u2
. /scan.sh
deb() { echo "/cache/$1_$2_$ARCH.deb"; }
phpfixed() { # expected-exit pid: run phpfixed here and check its verdict (check.py)
  rc=0
  (cd / && python3 -m phpfixed --cve CVE-2024-6119 --json) > /tmp/pf.json || rc=$?
  { echo "\$ python3 -m phpfixed --cve CVE-2024-6119 --json   (exit $rc)"; cat /tmp/pf.json
    python3 /check.py "$rc" "$1" "$2" /tmp/pf.json || echo "CHECK FAIL (check.py error)"; } > "/out/$MODE-phpfixed.txt" 2>&1
}
dpkg-deb -x "$(deb libssl3 $OLD)" /tmp/official-old
dpkg-deb -x "$(deb libssl3 $NEW)" /tmp/official-new
hashes() { # sha256 of each library: on disk now, in the official old and new packages
  for d in / /tmp/official-old/ /tmp/official-new/; do
    sha256sum "$d"usr/lib/*-linux-gnu/libssl.so.3 "$d"usr/lib/*-linux-gnu/libcrypto.so.3
  done
}

if [ "$MODE" = stale ]; then
  apt-get update -qq
  NEEDRESTART_SUSPEND=1 apt-get install -y -qq --no-install-recommends needrestart procps python3 >/dev/null
  dpkg -i "$(deb libssl3 $OLD)" "$(deb openssl $OLD)" >/dev/null
  cd /tmp
  openssl req -x509 -newkey rsa:2048 -nodes -keyout k -out c -subj /CN=demo -days 1 2>/dev/null
  openssl s_server -www -key k -cert c -accept 4433 </dev/null >/dev/null 2>&1 &
  pid=$!
  sleep 2
  kill -0 $pid
  run maps-before sh -c "dpkg-query -W libssl3 openssl; grep -E 'libssl|libcrypto' /proc/$pid/maps | sort -u -k6"
  scan before
  dpkg -i "$(deb libssl3 $NEW)" "$(deb openssl $NEW)" >/dev/null
  run maps-after sh -c "dpkg-query -W libssl3 openssl; ps -o pid,lstart,args -p $pid; grep -E 'libssl|libcrypto' /proc/$pid/maps | sort -u -k6"
  scan after
  run hashes hashes
  phpfixed 1 "$pid"
  run needrestart-batch needrestart -b -r l
  run needrestart-verbose needrestart -v -r l
  # What needrestart decides from: deleted or replaced mappings, no CVE data.
  run needrestart-source sh -c "dpkg-query -W needrestart
grep -rniE 'cve|vulnerab|fixed' /usr/sbin/needrestart /usr/share/perl5/NeedRestart.pm /usr/share/perl5/NeedRestart /etc/needrestart/hook.d || echo '(no match for cve|vulnerab|fixed in its code)'
awk 'NR>=497 && NR<=506 || NR>=522 && NR<=602 {print NR\": \"\$0}' /usr/sbin/needrestart"
else
  # Same vulnerable code, rebuilt with version 3.0.14-1+thirdparty1. dpkg
  # orders it above Debian's fixed 3.0.14-1~deb12u2.
  for p in libssl3 openssl; do
    dpkg-deb -R "$(deb $p $OLD)" /tmp/$p
    sed -i -e "s/^Version: .*/Version: 3.0.14-1+thirdparty1/" \
      -e "s/^Maintainer: .*/Maintainer: Example Third Party <nobody@example.invalid>/" \
      /tmp/$p/DEBIAN/control
    dpkg-deb -b /tmp/$p /tmp/$p.deb >/dev/null
  done
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends python3 >/dev/null
  dpkg -i /tmp/libssl3.deb /tmp/openssl.deb >/dev/null
  run package sh -c "dpkg-query -W -f '\${Package} \${Version} \${Maintainer}\n' libssl3 openssl
dpkg --compare-versions 3.0.14-1+thirdparty1 gt $NEW && echo 'dpkg: 3.0.14-1+thirdparty1 > $NEW'
"
  run hashes hashes
  scan after
  phpfixed 2 none
fi
