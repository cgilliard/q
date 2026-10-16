#!/bin/sh

set -e

# sparse: room for the state pages and their journal (src/pager.fam)
# The chain is the kernel's modules (scripts/files.txt), then the prog/ modules
# whose tests need the kernel's words (scripts/tests.txt), then the
# event loop's modules and the node, as the chain always ran (a Test block
# after src/loop.fam's never starts).
rm -f ./tmp/test_disk.img && truncate -s 4G ./tmp/test_disk.img
python3 scripts/net_host.py &
ECHO=$!
trap 'kill $ECHO 2>/dev/null' EXIT
./tools/fam --test --net --hostfwd=udp::47653-:47653,hostfwd=tcp:127.0.0.1:47653-:47653,hostfwd=tcp:127.0.0.1:47656-:47656 --disk=./tmp/test_disk.img --append=./resources/akjv.txt.gz `sed 's| src/rng.fam.*||' scripts/files.txt` `cat scripts/tests.txt` src/rng.fam src/loop.fam src/kernel.fam
