#!/bin/sh
# Builds a single-file phpfixed (python3 -m zipapp; stdlib only) and its SHA-256.
#
#   ci/zipapp.sh [outdir]          (default: dist/)
#
# Install as root, root-owned, and check the hash:
#   install -o root -g root -m 0755 dist/phpfixed /usr/local/bin/phpfixed
#   sha256sum /usr/local/bin/phpfixed      (must equal the hash in dist/phpfixed.sha256)
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
out=$(mkdir -p "${1:-$repo/dist}" && cd "${1:-$repo/dist}" && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/phpfixed/data"
cp "$repo"/phpfixed/*.py "$stage/phpfixed/"
cp "$repo"/phpfixed/data/*.json "$stage/phpfixed/data/"
# Not zipapp -m: its generated main drops the return value, so every run would exit 0.
printf 'import sys\nfrom phpfixed.cli import main\nsys.exit(main())\n' > "$stage/__main__.py"
# Fixed mtimes and modes, so the same tree always gives the same SHA-256.
chmod -R u=rwX,go=rX "$stage"
find "$stage" -exec touch -h -d 1980-01-02T00:00:00Z {} +
python3 -m zipapp "$stage" -o "$out/phpfixed" -p /usr/bin/python3
cd "$out"
sha256sum phpfixed > phpfixed.sha256
cat phpfixed.sha256
