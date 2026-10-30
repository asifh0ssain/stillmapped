# Known issues

Low-severity findings outside [THREAT_MODEL.md](THREAT_MODEL.md), or inside it
but unable to cause a false `fixed` or a false exit 0 in any setup the reviews
could build. Each one names the review that found it.

## rpm -V lines are matched by the mapped path only

Review 3, #7 (suspected, not reproduced). `rpm -qf` resolves symlinked
directories, so a package whose database path runs through a symlinked
directory could report a changed file under its database path. That line
would not end with the mapped path, and the change would be missed. No
bundled distro package installs libraries through a symlinked directory.
Fix idea: treat any `S`, `5`, `?` or `missing` line for the package as a
failure, or map database paths through the process root before comparing.

## Single read without a short-read check

Review 3, #8 (suspected, not reproduced). `_slurp` reads a file with one
`os.read` of its size. On FUSE or NFS a short read could hash only a common
prefix of two files. Fix idea: read until the size is reached and fail on a
short read.
