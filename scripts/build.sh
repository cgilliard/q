#!/bin/sh
set -e

CPU="rv32,zicsr=true,m=false,a=false,f=false,d=false,c=false,\
zawrs=false,zfa=false,zfh=false,zfhmin=false,zcb=false,\
zcd=false,zcf=false,zcmp=false,zcmt=false,zifencei=false"
MEM="128M"    # the virt default; lib/stdlib.fam's init lays the stacks out for exactly this

serial_qemu() {  # serial_qemu INFILE OUTFILE [extra qemu args...]
	sin=$1; sout=$2; shift 2
	sock=0
	case "$(uname -s)" in MINGW*|MSYS*) sock=1 ;; esac
	[ "$FAM_SERIAL" = "socket" ] && sock=1
	if [ "$sock" = 1 ]; then
		port=$((20000 + $$ % 20000))
		qemu-system-riscv32 \
			-machine virt -m "$MEM" -cpu "$CPU" \
			-display none -bios none \
			-chardev socket,id=ser0,host=127.0.0.1,port=$port,server=on,wait=on \
			-serial chardev:ser0 \
			"$@" &
		qpid=$!
		tools/serial_pump "$port" "$sin" "$sout"
		wait $qpid
	else
		qemu-system-riscv32 \
			-machine virt -m "$MEM" -cpu "$CPU" \
			-display none -bios none \
			-chardev file,id=ser0,path="$sout",input-path="$sin" \
			-serial chardev:ser0 \
			"$@"
	fi
}

run() {
	out=$1; asm=$2; shift 2
	disk_args=""; disk=""
	if [ "$1" = "--disk" ]; then
		disk=$2
		disk_args="-drive file=$disk,format=raw,if=none,id=hd0 \
-device virtio-blk-device,drive=hd0"
		shift 2
	fi
	[ $# -gt 0 ] && echo "Building $* → $out" >&2
	stream="$out.in.$$"
	([ $# -gt 0 ] && cat "$@"; printf '\004') > "$stream"
	serial_qemu "$stream" "$out" \
		-device loader,file="$asm",addr=0x80000000 \
		$disk_args
	rm -f "$stream"
}

# fsize FILE — size in bytes.  Portable: GNU stat spells it `-c %s`, BSD/macOS
# `-f %z`; `wc -c` works everywhere (tr strips BSD wc's leading padding).
fsize() { wc -c < "$1" | tr -d ' \t'; }

pack() {
        in=$1; out=$2
        echo "Packing $in → $out" >&2
        N=$(fsize "$in")
        stream="$out.in.$$"
        { printf "$(printf '\\%03o' $((N&255)) $(((N>>8)&255)) $(((N>>16)&255)) $(((N>>24)&255)))"
          cat "$in"
        } > "$stream"
        serial_qemu "$stream" "$out" -device loader,file=bin/fampack,addr=0x80000000
        rm -f "$stream"
}

patch_config() {
        bin=$1; data=$2
        echo "Patching $bin (bin_size + hash of $data)" >&2
        N=$(fsize "$data")
        NCHUNKS=$(( (N + 1023) / 1024 ))      # tabernacle fetches 1 KiB chunks (src/image.fam)
        TAB_SIZE=$(fsize "$bin")
        # Layout at end of tabernacle: [nchunks 4B][bin_size 4B][hash 32B]
        # Write nchunks (LE) at TAB_SIZE-40
        printf "$(printf '\\%03o' $((NCHUNKS&255)) $(((NCHUNKS>>8)&255)) $(((NCHUNKS>>16)&255)) $(((NCHUNKS>>24)&255)))" \
                | dd of="$bin" bs=1 seek=$((TAB_SIZE - 40)) conv=notrunc 2>/dev/null
        # Write bin_size (LE) at TAB_SIZE-36
        printf "$(printf '\\%03o' $((N&255)) $(((N>>8)&255)) $(((N>>16)&255)) $(((N>>24)&255)))" \
                | dd of="$bin" bs=1 seek=$((TAB_SIZE - 36)) conv=notrunc 2>/dev/null
        # Write hash at TAB_SIZE-32.  gen_hash reads its input via the loader
        # (no serial input, so feed an empty stream) and emits the digest on
        # the serial output file.
        ghash_input="$bin.ghin.$$"
        ghash_out="$bin.ghout.$$"
        ghash_nul="$bin.ghnul.$$"
        { printf "$(printf '\\%03o' $((N&255)) $(((N>>8)&255)) $(((N>>16)&255)) $(((N>>24)&255)))"
          cat "$data"
        } > "$ghash_input"
        : > "$ghash_nul"
        serial_qemu "$ghash_nul" "$ghash_out" \
                -device loader,file=bin/gen_hash,addr=0x80000000 \
                -device loader,file="$ghash_input",addr=0x80800000 2>/dev/null
        HASH=$(cat "$ghash_out")
        rm -f "$ghash_input" "$ghash_out" "$ghash_nul"
        [ $(echo $HASH | wc -w) -eq 8 ] || { echo "gen_hash failed"; exit 1; }
        LEHEX=""
        for word in $HASH; do
                LEHEX="${LEHEX}$(echo "$word" | sed 's/\(..\)\(..\)\(..\)\(..\)/\4\3\2\1/')"
        done
        echo "$LEHEX" | xxd -r -p | dd of="$bin" bs=1 seek=$((TAB_SIZE - 32)) conv=notrunc 2>/dev/null
}

run bin/fam0 fam0.seed src/fam0.fam0
cmp ./bin/fam0 ./fam0.seed
run bin/fam.uncompressed bin/fam0 src/fam.fam0
run bin/fampack bin/fam.uncompressed lib/stdlib.fam lib/asm.fam src/fampack.fam
pack bin/fam.uncompressed bin/fam
run bin/gen_hash bin/fam lib/stdlib.fam lib/asm.fam src/gen_hash.fam
run bin/tabernacle.uncompressed bin/fam0 src/tabernacle.fam0
run bin/kernel.bin bin/fam lib/stdlib.fam lib/build.fam `cat scripts/files.txt`

# the programs the node installs in its store at boot (src/exec.fam)
./tools/fam --prog -o bin/hello.bin prog/hello.fam
./tools/fam --prog -o bin/crash.bin prog/crash.fam
./tools/fam --prog -o bin/init.bin prog/init.fam
./tools/fam --prog -o bin/udpecho.bin lib/pnet.fam src/eth.fam src/ip.fam src/udp.fam src/tcp.fam lib/pstack.fam prog/udpecho.fam
./tools/fam --prog -o bin/wm.bin lib/pnet.fam src/eth.fam src/ip.fam src/udp.fam src/tcp.fam lib/pstack.fam lib/pkv.fam prog/http.fam prog/wm.fam
./scripts/progs.sh bin/progs.blob hello=bin/hello.bin crash=bin/crash.bin init=bin/init.bin udpecho=bin/udpecho.bin wm=bin/wm.bin

# the image padded to a page (the stdlib's init starts the data on one), 20 KiB
# of zeros over the node's RID stack and variables (the image is not loaded
# into zeroed memory), then the programs blob (the first thing the node's heap
# holds: src/kernel.fam keeps it), then the text
truncate -s $(( ( $(fsize bin/kernel.bin) + 4095 ) / 4096 * 4096 )) bin/kernel.bin
head -c 20480 /dev/zero >> bin/kernel.bin
cat bin/progs.blob >> bin/kernel.bin
cat resources/akjv.txt.gz >> bin/kernel.bin
patch_config bin/tabernacle.uncompressed bin/kernel.bin
pack bin/tabernacle.uncompressed bin/tabernacle
