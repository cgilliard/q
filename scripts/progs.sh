#!/bin/sh
# Pack program images into the blob src/exec.fam's proginst installs at boot:
#   progs.sh OUT NAME=IMAGE ...
# OUT: "QPRG", the count, then per program a 16-byte NUL-padded name (at most
# 15 characters) and the image's size, then the images, each padded to 4 bytes.
# scripts/build.sh appends the blob to the node's image right after the 20 KiB
# of zeros, so it is the first thing the node's heap holds (src/kernel.fam).
set -e
OUT=$1; shift
le32() { printf "$(printf '\\%03o' $(($1&255)) $((($1>>8)&255)) $((($1>>16)&255)) $((($1>>24)&255)))"; }
fsize() { wc -c < "$1" | tr -d ' \t'; }
for a in "$@"; do
	n=${a%%=*}; f=${a#*=}
	[ ${#n} -le 15 ] || { echo "progs.sh: name over 15 characters: $n" >&2; exit 1; }
	[ -f "$f" ] || { echo "progs.sh: no such image: $f" >&2; exit 1; }
done
{
	printf 'QPRG'; le32 $#
	for a in "$@"; do
		n=${a%%=*}; f=${a#*=}
		printf '%s' "$n"; head -c $((16 - ${#n})) /dev/zero
		le32 $(fsize "$f")
	done
	for a in "$@"; do
		f=${a#*=}; s=$(fsize "$f"); pad=$(( (4 - s % 4) % 4 ))
		cat "$f"
		if [ $pad -gt 0 ]; then head -c $pad /dev/zero; fi
	done
} > "$OUT"
echo "$OUT: $# program(s)"
