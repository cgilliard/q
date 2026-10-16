#!/bin/sh
# The node's HTTP and WebSocket performance as a client sees it through QEMU's
# port forward: boot the node from the disk image (quiet, on host port 8090 so
# a running dev node is not disturbed; its UDP endpoint on host port 3747), run scripts/load.py's matrix, stop it.
# Needs scripts/build.sh and scripts/makenode.sh first.  The in-guest cost of
# the same operations without a network is in `./scripts/bench.sh` (httpreq,
# httpconn, wsconn, wsecho, wsbcast in prog/http.fam).
set -e
HTTP=${HTTP:-8090}
UDP=${UDP:-3747}
LOG=${LOG:-./tmp/perf_node.log}
mkdir -p ./tmp
HTTP=$HTTP PORT=$UDP QUIET=1 setsid ./scripts/boot.sh > "$LOG" 2>&1 &
BOOT=$!
trap 'kill -- -$BOOT 2>/dev/null' EXIT                 # the whole group: boot.sh, q32/qemu, cat
for i in $(seq 1 120); do grep -q "serving http" "$LOG" 2>/dev/null && break; sleep 0.5; done
grep -q "serving http" "$LOG" || { echo "the node did not come up (see $LOG)"; exit 1; }
sleep 0.5
L="python3 scripts/load.py"
echo "HTTP, keep-alive (one connection per worker, requests in turn)"
$L http   -p $HTTP -c 1 -n 2000
$L http   -p $HTTP -c 4 -n 1000
$L http   -p $HTTP -c 1 -n 2000 --path /nope
echo "HTTP, a connection per request (connect, GET, close)"
$L httpnc -p $HTTP -c 1 -n 500
$L httpnc -p $HTTP -c 2 -n 300
$L httpnc -p $HTTP -c 6 -n 100
echo "WebSocket echo round trips (a masked text message, the 'you said' reply)"
$L ws     -p $HTTP -c 1 -n 2000 -s 5
$L ws     -p $HTTP -c 1 -n 500  -s 2000
$L ws     -p $HTTP -c 8 -n 500  -s 5
echo "WebSocket ticks (the node's broadcast once a second)"
$L ticks  -p $HTTP -c 8 -t 3
echo "UDP echo round trips to the node's endpoint (datagram out, the same back)"
$L udp    -p $UDP -c 1 -n 5000 -s 64
$L udp    -p $UDP -c 4 -n 2000 -s 64
$L udp    -p $UDP -c 1 -n 2000 -s 1400
echo "UDP flood (datagrams back to back, then what comes back)"
$L udpflood -p $UDP -c 1 -n 5000 -s 64
$L udpflood -p $UDP -c 1 -n 2000 -s 1400
