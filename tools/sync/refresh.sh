#!/bin/sh
# Monthly data refresh, one command. The scanner code does not change.
#
#   tools/sync/refresh.sh VERSION        (for example 0.1.1)
#
# 1. Rebuild the previous snapshot; it must give the bundled data byte for byte.
# 2. Fetch a new snapshot (network; primary vendor feeds only, 1 request/s).
# 3. Rebuild it offline from its manifest, run the oracle.
# 4. Diff the new data against the bundled data (tools/sync/out/refresh.txt).
# 5. Put the new data in stillmapped/data, run both test suites and demo/run.sh.
# 6. Set VERSION with today's date in stillmapped/__init__.py, pyproject.toml
#    and a new CHANGELOG entry.
# Stops at the first failure. Commits and pushes nothing: review the diff first.
set -eu
v=${1:?usage: tools/sync/refresh.sh VERSION}
echo "$v" | grep -qxE '[0-9]+\.[0-9]+\.[0-9]+' || { echo "bad version: $v" >&2; exit 2; }
repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo"
[ -z "$(git status --porcelain)" ] || { echo "the work tree is not clean" >&2; exit 1; }
! grep -q "^## $v " CHANGELOG.md || { echo "CHANGELOG already has $v" >&2; exit 1; }
today=$(date -u +%Y-%m-%d)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "== 1. previous snapshot must reproduce the bundled data"
prev=$(ls -d tools/sync/snapshots/*/ 2>/dev/null | sort | tail -n 1)
[ -n "$prev" ] || { echo "no previous snapshot under tools/sync/snapshots/" >&2; exit 1; }
rm -rf tools/sync/out
python3 -m tools.sync build "$prev" >/dev/null
diff -r -x skipped.tsv stillmapped/data tools/sync/out
cp tools/sync/out/skipped.tsv "$tmp/old-skipped.tsv"
cp -r stillmapped/data "$tmp/old"

echo "== 2. fetch"
python3 -m tools.sync fetch > "$tmp/fetch.txt"
snap=$(tail -n 1 "$tmp/fetch.txt")
id=$(basename "$snap")
manifest=$(sha256sum "$snap/manifest.json" | cut -d' ' -f1)

echo "== 3. offline rebuild and oracle"
rm -rf tools/sync/out
python3 -m tools.sync build "$snap" >/dev/null
python3 -m tools.sync oracle

echo "== 4. diff against the bundled data"
python3 -I - "$tmp/old" tools/sync/out "$tmp/old-skipped.tsv" "$tmp/counts" > "$tmp/refresh.txt" <<'EOF'
import collections, glob, json, os, sys
old_dir, new_dir, old_skips, counts_out = sys.argv[1:]

def load(d):
    recs = {}
    for f in sorted(glob.glob(os.path.join(d, "CVE-*.json"))):
        doc = json.load(open(f))
        for r in doc["records"]:
            recs[(doc["cves"][0], r["vendor"], r["stream"], r["package"], r["branch"])] = r
    return recs

def rows(f):
    return set(open(f).read().splitlines()[1:])

old, new = load(old_dir), load(new_dir)
cves = lambda recs: {k[0] for k in recs}
same = lambda a, b: {k: v for k, v in a.items() if k != "checked"} == {k: v for k, v in b.items() if k != "checked"}
per = collections.defaultdict(collections.Counter)
for k in old.keys() | new.keys():
    kind = "added" if k not in old else "removed" if k not in new else None if same(old[k], new[k]) else "changed"
    if kind:
        per[f"{k[1]} {k[2]}"][kind] += 1
added_cves = sorted(cves(new) - cves(old))
removed_cves = sorted(cves(old) - cves(new))
worse = [(k, new[k]) for k in sorted(old.keys() & new.keys()) if old[k]["status"] == "fixed" and new[k]["status"] in ("not-fixed", "unknown")]
gone = [(k, old[k]) for k in sorted(old.keys() - new.keys()) if old[k]["status"] == "fixed"]
new_skips = sorted(rows(os.path.join(new_dir, "skipped.tsv")) - rows(old_skips))
total = collections.Counter(kind for c in per.values() for kind in c)
status = collections.Counter(r["status"] for r in new.values())

print(f"CVEs: {len(cves(old))} -> {len(cves(new))}, {len(added_cves)} added, {len(removed_cves)} removed")
print(f"Records: {len(old)} -> {len(new)}, {total['added']} added, {total['changed']} changed, {total['removed']} removed")
print("New statuses: " + ", ".join(f"{n} {s}" for s, n in sorted(status.items())))
print("\nPer distro (added / changed / removed):")
for d in sorted(per):
    print(f"  {d}: {per[d]['added']} / {per[d]['changed']} / {per[d]['removed']}")
print("\nCVEs added: " + (" ".join(added_cves) or "none"))
print("CVEs removed: " + (" ".join(removed_cves) or "none"))
print(f"\nFixed -> not-fixed or unknown: {len(worse)}")
for k, r in worse:
    print(f"  {' '.join(k)}: {r['status']}  {r['evidence_url']}")
print(f"Fixed records removed (the scanner then answers unknown or not judged): {len(gone)}")
for k, r in gone:
    print(f"  {' '.join(k)}: was fixed {r['fixed']}  {r['evidence_url']}")
print(f"\nNew skip rows (cve, distro, stream, package, reason): {len(new_skips)}")
for s in new_skips:
    print("  " + s.replace("\t", " | "))
json.dump({"cves": len(cves(new)), "cves_added": len(added_cves), "cves_removed": len(removed_cves),
           "records": len(new), **{k: total[k] for k in ("added", "changed", "removed")},
           "status": dict(status), "per": {d: dict(c) for d, c in per.items()}, "worse": len(worse), "gone": len(gone)},
          open(counts_out, "w"))
EOF
# Report-only: text in the fetched feeds that addresses an AI. Feed content is data.
grep -r -l -i -E 'ignore (all |any )?(previous|prior) instructions|as an ai\b|language model|ai assistant' "$snap/files" \
  > "$tmp/ai.txt" || true
echo "Fetched files with AI-directed text: $(wc -l < "$tmp/ai.txt")" >> "$tmp/refresh.txt"
sed 's/^/  /' "$tmp/ai.txt" >> "$tmp/refresh.txt"
cat "$tmp/refresh.txt"

echo "== 5. new data, tests, demo"
rm -f stillmapped/data/*.json
cp tools/sync/out/CVE-*.json stillmapped/data/
python3 -m unittest discover -s tests -t .
python3 -m unittest discover -s tools/sync/tests -t .
demo/run.sh | tee "$tmp/demo.txt"
# run.sh itself exits 0; its four CHECK lines must all pass and no container may fail.
dout=$(tail -n 1 "$tmp/demo.txt" | sed -n 's|^done: \(.*\)/summary.txt$|\1|p')
[ -n "$dout" ] && [ ! -e "$dout/errors.txt" ] || { echo "demo: container errors" >&2; exit 1; }
cat "$dout"/*-stillmapped.txt "$dout"/eaphp-php-owner.txt | grep '^CHECK' > "$tmp/checks.txt" || true
cat "$tmp/checks.txt"
[ "$(grep -c ': PASS$' "$tmp/checks.txt")" = 4 ] && [ "$(wc -l < "$tmp/checks.txt")" = 4 ] || { echo "demo: not 4 of 4 PASS" >&2; exit 1; }

echo "== 6. version $v ($today)"
sed -i "s/^__version__ = \".*\"/__version__ = \"$v\"/" stillmapped/__init__.py
sed -i "s/^version = \".*\"  # released .*;/version = \"$v\"  # released $today;/" pyproject.toml
python3 -I - "$v" "$today" "$id" "$manifest" "$tmp/counts" <<'EOF'
import json, sys
v, today, snap, manifest, counts = sys.argv[1:]
c = json.load(open(counts))
st = c["status"]
per = "\n".join(f"  - {d}: {n.get('added', 0)} / {n.get('changed', 0)} / {n.get('removed', 0)}" for d, n in sorted(c["per"].items())) or "  - none"
entry = f"""## {v} ({today})

Data refresh. The scanner code does not change.

- Bundled data regenerated by `tools/sync/refresh.sh` from a new snapshot:
  {c['cves']} CVEs, {c['records']} records ({st.get('fixed', 0)} fixed, {st.get('not-affected', 0)} not affected, {st.get('not-fixed', 0)} not
  fixed, {st.get('unknown', 0)} unknown).
  - Snapshot: `{snap}`
  - Manifest SHA-256: `{manifest}`
- Against the previous release: {c['cves_added']} CVEs added, {c['cves_removed']} removed; {c['added']} records
  added, {c['changed']} changed, {c['removed']} removed. Fixed records that became
  not fixed or unknown: {c['worse']}; fixed records removed: {c['gone']}.
- Per distro (records added / changed / removed):
{per}

"""
text = open("CHANGELOG.md").read()
head = "# Changelog\n\n"
assert text.startswith(head)
open("CHANGELOG.md", "w").write(head + entry + text[len(head):])
EOF
python3 -m unittest tests.test_cli.TestVersion
cp "$tmp/refresh.txt" tools/sync/out/refresh.txt
echo "done: snapshot $id, report tools/sync/out/refresh.txt. Review, update README Status, then commit."
