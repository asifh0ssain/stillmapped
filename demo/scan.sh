#!/bin/sh
# Sourced by deb.sh and eaphp.sh. Scans this container's root with the
# cached scanners and databases, no network. The cache is mounted read-only,
# so the databases are copied to /tmp first.
bin=/cache/bin-$ARCH
mkdir -p /tmp/trivy
cp -r /cache/trivy/db /tmp/trivy/db
cp -r /cache/grype /tmp/grype
export TRIVY_SKIP_VERSION_CHECK=true GRYPE_DB_CACHE_DIR=/tmp/grype
export GRYPE_DB_AUTO_UPDATE=false GRYPE_CHECK_FOR_APP_UPDATE=false

run() { # name command...: save the command and its output to /out
  f=/out/$MODE-$1.txt; shift
  printf '$ %s\n' "$*" > "$f"
  "$@" >> "$f" 2>&1 || echo "(exit $?)" >> "$f"
}

scan() { # label
  run "trivy-$1" "$bin/trivy" rootfs --cache-dir /tmp/trivy --skip-db-update \
    --scanners vuln --pkg-types os /
  run "grype-$1" "$bin/grype" dir:/ --exclude './proc/**' --exclude './sys/**' \
    --exclude './cache/**' --exclude './out/**' --exclude './tmp/**'
}
