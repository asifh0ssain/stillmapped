#!/bin/sh
# Runs in almalinux:9 (amd64). Installs the oldest ea-php82 CLI that cPanel's
# public EA4 repository still serves, then scans with Trivy, Grype and the
# current phpfixed. phpfixed has no ea-php records, so it must answer
# unknown with exit 2; anything else is a phpfixed bug.
set -eu
MODE=eaphp
ARCH=amd64
. /scan.sh
rpm --import https://securedownloads.cpanel.net/cPanelPublicPkgKey.asc
curl -fsSL -o /etc/yum.repos.d/EA4.repo https://securedownloads.cpanel.net/EA4/EA4.repo
run versions dnf -q --showduplicates list ea-php82-php-cli
v=$(dnf -q --showduplicates list ea-php82-php-cli | awk '/^ea-php82-php-cli/ {print $2; exit}')
dnf -q -y --setopt=install_weak_deps=False install "ea-php82-php-cli-$v" >/dev/null
run package sh -c "rpm -qa 'ea-php82*' | sort; /opt/cpanel/ea-php82/root/usr/bin/php -v"
scan after
# Which package owns the binary that printed the version, and what the
# runtime package installs.
php=/opt/cpanel/ea-php82/root/usr/bin/php
run php-owner sh -c "ls -l $php; readlink -f $php; rpm -qf $php \$(readlink -f $php)
case \$(rpm -qf --qf '%{NAME}' \$(readlink -f $php)) in
  ea-php82-php-cli) echo 'CHECK php binary owned by ea-php82-php-cli: PASS' ;;
  *) echo 'CHECK php binary owned by ea-php82-php-cli: FAIL' ;;
esac"
run runtime-files rpm -ql ea-php82-runtime
# Did cPanel backport the 8.2.35 fixes into this build? Its changelog says.
run changelog rpm -q --changelog ea-php82-php-cli ea-php82-runtime
run changelog-check sh -c "rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE} built %{BUILDTIME:date}\n' ea-php82-php-cli ea-php82-runtime
rpm -q --changelog \$(rpm -qa 'ea-php82*') | grep -inE 'CVE-2026-10961[89]|GHSA-w8hw-w9fx-j79w|GHSA-6wmf-4rv5-p3rp|8[.]2[.]35' || echo '(no changelog entry mentions CVE-2026-109618, CVE-2026-109619, their GHSA IDs or 8.2.35)'"
# Is a silent Grype a miss, or a CVE its database lacks? PHP 8.2.35
# (2026-10-22) fixed CVE-2026-109618 and CVE-2026-109619.
run grype-db-search "$bin/grype" db search --vuln CVE-2026-109618

cd /
rc=0
python3 -m phpfixed --json > /tmp/phpfixed.json || rc=$?
{
  echo "\$ python3 -m phpfixed --json   (exit $rc)"
  cat /tmp/phpfixed.json
  python3 - "$rc" <<'EOF'
import json, sys
r = json.load(open("/tmp/phpfixed.json"))
ea = [x for x in r["results"] if x["build"]["vendor"] == "cpanel"]
ok = sys.argv[1] == "2" and ea and all(x["status"] == "unknown" for x in ea)
print("CHECK unknown + exit 2 on ea-php:", "PASS" if ok else "FAIL (phpfixed bug)")
EOF
} > /out/eaphp-phpfixed.txt 2>&1
