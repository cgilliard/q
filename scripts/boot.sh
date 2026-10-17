#!/bin/bash
# Boot the node from the disk image and attach this terminal to its console:
# the shell on the UART (prog/sh.fam, the init.d/sh link).  Keys go to the node
# as they are typed (the shell echoes them), Ctrl-] quits.  The node serves
# http://127.0.0.1:8080/ through the port forward.  Environment: HTTP=port
# (host side, default 8080), PORT=the host port forwarded to the node's UDP
# 3737 (default 3737), DISK=image (default ./data/disk.img), TRACE=1 keeps the
# node's request trace on the console (off now that a shell lives there; QUIET
# is accepted and means nothing).  Without a terminal on stdin (a script), what
# arrives on stdin goes to the console and the node runs until it is killed.
PORT=${PORT:-3737}
HTTP=${HTTP:-8080}
DISK=${DISK:-./data/disk.img}
FIFO=$(mktemp -u)
mkfifo "$FIFO"
# the node's output through a pipe: QEMU's stdio chardev makes what it writes to
# non-blocking, which must not be the terminal the keys are read from
( ./tools/q32 bin/tabernacle --disk="$DISK" --net --hostfwd=udp::$PORT-:3737,hostfwd=tcp:127.0.0.1:$HTTP-:8080 < "$FIFO" 2>&1 | cat ) &
QPID=$!
exec 3> "$FIFO"
rm -f "$FIFO"
printf '%s 1 10000 1\004%s' "$PORT" "${TRACE:+}${TRACE:-q}" >&3            # the boot config, then 'q' unless tracing
if [ -t 0 ]; then
	SAVED=$(stty -g)
	trap 'stty "$SAVED"; pkill -P $QPID -f "^qemu-system-riscv32 " 2>/dev/null; wait $QPID 2>/dev/null; echo' EXIT
	stty -icanon -echo -isig -ixon -ixoff min 1 time 0   # keys straight through: Ctrl-S and Ctrl-Q too
	while IFS= read -r -n1 -d '' c; do
		[ "$c" = $'\x1d' ] && break
		[ -z "$c" ] && c=$'\n'
		printf '%s' "$c" >&3 2>/dev/null || break          # the node is gone
	done
else
	cat >&3 &                         # stdin to the console for as long as the node runs
	CPID=$!
	wait $QPID
	kill $CPID 2>/dev/null
fi
