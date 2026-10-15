#!/bin/sh
# Boot the node from the disk image.  It serves http://127.0.0.1:8080/ (a page
# with a WebSocket) through the port forward and traces every request on
# stdout.  Environment: HTTP=port (host side, default 8080), PORT=the node's
# UDP port (default 3737), QUIET=1 turns the trace off (scripts/perf.sh).
set -e
PORT=${PORT:-3737}
HTTP=${HTTP:-8080}
DISK=${DISK:-./data/disk.img}
run() {
	./tools/q32 bin/tabernacle \
		--disk="$DISK" \
		--net \
		--hostfwd=udp::$PORT-:$PORT,hostfwd=tcp:127.0.0.1:$HTTP-:8080 | cat
}

printf '%s 1 10000 1\004%s' "$PORT" "${QUIET:+q}" | run
