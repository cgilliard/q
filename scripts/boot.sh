#!/bin/sh
set -e
PORT=3737
API=3738
DISK=${DISK:-./data/disk.img}
run() {
	./tools/q32 bin/tabernacle \
		--disk="$DISK" \
		--net \
		--hostfwd=udp::$PORT-:$PORT,hostfwd=tcp:127.0.0.1:$API-:$API | cat
}

printf '%s 1 10000 1\004' "$PORT" | run
