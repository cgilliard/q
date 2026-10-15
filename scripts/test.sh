#!/bin/sh

set -e

# sparse: room for the state pages and their journal (src/pager.fam)
rm -f ./tmp/test_disk.img && truncate -s 4G ./tmp/test_disk.img
python3 scripts/udp_echo.py 47654 &
ECHO=$!
trap 'kill $ECHO 2>/dev/null' EXIT
./tools/fam --test --net --hostfwd=udp::47653-:47653 --disk=./tmp/test_disk.img --append=./resources/akjv.txt.gz `cat scripts/files.txt` `cat scripts/tests.txt`
