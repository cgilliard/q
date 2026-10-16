#!/bin/sh
# Write the boot image (bin/kernel.bin from scripts/build.sh: the kernel with
# the programs and the text appended) to the start of the
# disk image tabernacle boots from (DISK, data/disk.img by default).  The
# image is sparse, 128 GiB when made here:
# the node keeps its store 32 MiB in (pgbase, set in src/kernel.fam), and
# rewriting the boot image leaves them alone -- a new build keeps its chain.
set -e
IMG=${DISK:-./data/disk.img}
N=$(wc -c < bin/kernel.bin | tr -d ' \t')
rm -f $IMG
[ "$N" -lt 33554432 ] || { echo "bin/kernel.bin is over 32 MiB: it would overrun the chain"; exit 1; }
[ -e "$IMG" ] || truncate -s 128G "$IMG"
[ $(wc -c < "$IMG" | tr -d ' \t') -ge 4294967296 ] || truncate -s 4G "$IMG"
dd if=bin/kernel.bin of="$IMG" conv=notrunc 2>/dev/null
echo "$IMG: $N bytes written"
