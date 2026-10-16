#!/usr/bin/env python3
# gen_proc.py — generate src/proc.fam (threads + lottery scheduler).
#
# The machine-code fragments (trap entry/exit, CSR access, table walks) are
# written below in GNU assembler syntax and assembled with riscv64-unknown-elf-as
# so nothing is hand-encoded; each fam line carries its disassembly.  Like
# tools/s2fam0_*.py this is a one-time generator: src/proc.fam is checked in and
# scripts/build.sh compiles it with bin/fam.  Rerun after editing this file:
#     python3 tools/gen_proc.py            # writes src/proc.fam
#     python3 tools/gen_proc.py --debug    # with scheduler tracing on the UART
import os, re, subprocess, sys, tempfile, textwrap

AS, ODUMP = "riscv64-unknown-elf-as", "riscv64-unknown-elf-objdump"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def asm(src):
    """Assemble an RV32I+Zicsr snippet; return fam lines `XXXXXXXX ,   \\ insn`
    (the 4 bytes in memory order: fam's `,` emits big-endian)."""
    with tempfile.TemporaryDirectory() as d:
        s, o = os.path.join(d, "f.S"), os.path.join(d, "f.o")
        open(s, "w").write(textwrap.dedent(src).rstrip("\n") + "\n")
        subprocess.run([AS, "-march=rv32i_zicsr", "-mabi=ilp32", "-o", o, s], check=True)
        dis = subprocess.run([ODUMP, "-d", o], check=True, capture_output=True, text=True).stdout
    out = []
    for ln in dis.splitlines():
        m = re.match(r"^\s*[0-9a-f]+:\t([0-9a-f]{8})\s+(.*)$", ln)
        if m:
            b = bytes.fromhex(m.group(1))[::-1]
            out.append(f"{b.hex().upper()} ,   \\ {re.sub(r'\s+', ' ', m.group(2)).strip()}")
    return "\n".join(out)

# ── TCB layout (bytes) ───────────────────────────────────────────────────
#   4*n   saved x_n (n = 1..31)        0x80 pc        0x84 state (0 free,
#   1 runnable, 2 sleeping, 3 waiting)   0x88 tickets   0x8C pid
#   0x90 wait mask (event subscription)   0x94 wake lo   0x98 wake hi
#   0x9C pending events   size 0xA0
# ── kernel block K (bytes) ───────────────────────────────────────────────
#   0 current tcb   4 t1 stash   8 table base   C rng state   10 slot pool
#   14 kernel sp   18 kernel s8   1C kernel s11   20 kernel gp
#   24 quantum (mtime ticks)   28 tick count   2C unclaimed IRQ events

SAVE = asm("""
    csrrw   t0, mscratch, t0        # t0 = K, mscratch = thread's t0
    sw      t1, 4(t0)               # stash t1 in K
    lw      t1, 0(t0)               # t1 = current TCB
    sw      x1, 4(t1)
    sw      x2, 8(t1)
    sw      x3, 12(t1)
    sw      x4, 16(t1)
    sw      x7, 28(t1)
    sw      x8, 32(t1)
    sw      x9, 36(t1)
    sw      x10, 40(t1)
    sw      x11, 44(t1)
    sw      x12, 48(t1)
    sw      x13, 52(t1)
    sw      x14, 56(t1)
    sw      x15, 60(t1)
    sw      x16, 64(t1)
    sw      x17, 68(t1)
    sw      x18, 72(t1)
    sw      x19, 76(t1)
    sw      x20, 80(t1)
    sw      x21, 84(t1)
    sw      x22, 88(t1)
    sw      x23, 92(t1)
    sw      x24, 96(t1)
    sw      x25, 100(t1)
    sw      x26, 104(t1)
    sw      x27, 108(t1)
    sw      x28, 112(t1)
    sw      x29, 116(t1)
    sw      x30, 120(t1)
    sw      x31, 124(t1)
    csrr    t2, mscratch
    sw      t2, 20(t1)              # x5 (t0)
    lw      t2, 4(t0)
    sw      t2, 24(t1)              # x6 (t1)
    csrw    mscratch, t0            # mscratch = K again
    csrr    t2, mepc
    sw      t2, 128(t1)             # pc
    lw      sp, 20(t0)              # switch to the kernel's stacks
    lw      s8, 24(t0)
    lw      s11, 28(t0)
    lw      gp, 32(t0)
    lw      s10, 56(t0)             # and its variable base (a program has its own)
""")

RESTORE = asm("""
    csrr    t0, mscratch            # K
    lw      t1, 0(t0)               # TCB to resume
    lw      t2, 128(t1)
    csrw    mepc, t2
    lw      t2, 140(t1)             # the thread's record: K+0x34 + pid*0x300
    slli    t3, t2, 9
    slli    t2, t2, 8
    add     t2, t2, t3
    lw      t3, 52(t0)
    add     t2, t2, t3
    lw      t3, 8(t2)               # mode: 0 machine, 1 user
    li      t4, 0x1800
    csrc    mstatus, t4             # MPP = U ...
    bnez    t3, 1f
    csrs    mstatus, t4             # ... or M for a kernel thread; PMP is ignored there
    j       2f
1:  lw      t3, 12(t2)              # e0: the process image's base (a boundary only)
    srli    t3, t3, 2
    csrw    pmpaddr0, t3
    lw      t3, 16(t2)              # e1: up to the image's end, read + execute
    srli    t3, t3, 2
    csrw    pmpaddr1, t3
    lw      t3, 20(t2)              # e2: up to the process region's end, read + write
    srli    t3, t3, 2
    csrw    pmpaddr2, t3
    lw      t3, 0(t2)               # e3: the thread's own region, read + write (NAPOT)
    lw      t4, 4(t2)
    srli    t4, t4, 1
    addi    t4, t4, -1
    or      t3, t3, t4
    srli    t3, t3, 2
    csrw    pmpaddr3, t3
    li      t3, 0x040001FF          # e4: the UART page, read + write (NAPOT 4 KiB at 0x10000000)
    csrw    pmpaddr4, t3
    li      t3, 0x00802FFE          # e5: mtime, read only (NAPOT 8 bytes at 0x0200BFF8)
    csrw    pmpaddr5, t3
    li      t3, 0x1B0B0D00          # e3 NAPOT RW | e2 TOR RW | e1 TOR RX | e0 off
    csrw    pmpcfg0, t3
    li      t3, 0x191B              # e5 NAPOT R | e4 NAPOT RW
    csrw    pmpcfg1, t3
2:  li      t2, 0x80                # MPIE = 1: interrupts on after mret
    csrs    mstatus, t2
    lw      x1, 4(t1)
    lw      x2, 8(t1)
    lw      x3, 12(t1)
    lw      x4, 16(t1)
    lw      x7, 28(t1)
    lw      x8, 32(t1)
    lw      x9, 36(t1)
    lw      x10, 40(t1)
    lw      x11, 44(t1)
    lw      x12, 48(t1)
    lw      x13, 52(t1)
    lw      x14, 56(t1)
    lw      x15, 60(t1)
    lw      x16, 64(t1)
    lw      x17, 68(t1)
    lw      x18, 72(t1)
    lw      x19, 76(t1)
    lw      x20, 80(t1)
    lw      x21, 84(t1)
    lw      x22, 88(t1)
    lw      x23, 92(t1)
    lw      x24, 96(t1)
    lw      x25, 100(t1)
    lw      x26, 104(t1)
    lw      x27, 108(t1)
    lw      x28, 112(t1)
    lw      x29, 116(t1)
    lw      x30, 120(t1)
    lw      x31, 124(t1)
    lw      x5, 20(t1)
    lw      x6, 24(t1)
    mret
""")

SYSCALL = asm("""
    lw      a7, 0(sp)
    addi    sp, sp, 4
    ecall
""")

# emitter: write `li a7,1 ; ecall` to the output.  The two words come from the
# assembler (no hand-encoded constants).
def word_of(insn):
    line = asm(insn).splitlines()[0]
    return int.from_bytes(bytes.fromhex(line.split()[0]), "little")
EXIT_EMIT = asm(f"""
    li      t0, {word_of("li a7, 1"):#010x}
    sw      t0, 0(gp)
    addi    gp, gp, 4
    li      t0, {word_of("ecall"):#010x}
    sw      t0, 0(gp)
    addi    gp, gp, 4
""")

MCAUSE = asm("""
    csrr    t0, mcause
    addi    sp, sp, -4
    sw      t0, 0(sp)
""")

MTVAL = asm("""
    csrr    t0, mtval
    addi    sp, sp, -4
    sw      t0, 0(sp)
""")

MTVEC = asm("""
    lw      t0, 0(sp)
    addi    sp, sp, 4
    csrw    mtvec, t0
""")

MSCRATCH = asm("""
    lw      t0, 0(sp)
    addi    sp, sp, 4
    csrw    mscratch, t0
""")

INT_ON = asm("""
    li      t0, 0x880               # mie.MTIE | mie.MEIE
    csrs    mie, t0
    li      t0, 0x8                 # mstatus.MIE
    csrs    mstatus, t0
""")

INT_OFF = asm("""
    li      t0, 0x8
    csrc    mstatus, t0
""")

MTIME = asm("""
    lui     t0, 0x0200C             # CLINT mtime = 0x0200BFF8
1:  lw      t1, -4(t0)              # hi
    lw      t2, -8(t0)              # lo
    lw      t3, -4(t0)              # hi again
    bne     t1, t3, 1b
    addi    sp, sp, -8
    sw      t2, 4(sp)               # lo
    sw      t1, 0(sp)               # hi on top
""")

RTC = asm("""
    lui  t0, 0x101
    lw   t1, 0(t0)
    lw   t2, 4(t0)
    addi sp, sp, -8
    sw   t1, 4(sp)
    sw   t2, 0(sp)
""")
UDIV = asm("""
    lw   a2, 0(sp)
    lw   a1, 4(sp)
    lw   a0, 8(sp)
    addi sp, sp, 8
    li   t0, 32
1:  srli t2, a1, 31
    srli t1, a0, 31
    slli a1, a1, 1
    or   a1, a1, t1
    slli a0, a0, 1
    bnez t2, 3f
    bltu a1, a2, 2f
3:  sub  a1, a1, a2
    ori  a0, a0, 1
2:  addi t0, t0, -1
    bnez t0, 1b
    sw   a0, 0(sp)
""")
MTIMECMP = asm("""
    lw      t1, 0(sp)               # hi
    lw      t2, 4(sp)               # lo
    addi    sp, sp, 8
    lui     t0, 0x02004             # CLINT mtimecmp hart 0
    li      t3, -1
    sw      t3, 0(t0)               # lo = -1 first: no spurious match mid-update
    sw      t1, 4(t0)
    sw      t2, 0(t0)
""")

# ( table -- n )  sum of tickets over runnable TCBs
NTICKETS = asm("""
    lw      a0, 0(sp)
    li      a1, 0
    li      t0, 16                  # MAXT
1:  lw      t1, 132(a0)
    li      t2, 1
    bne     t1, t2, 2f
    lw      t1, 136(a0)
    add     a1, a1, t1
2:  addi    a0, a0, 160
    addi    t0, t0, -1
    bnez    t0, 1b
    sw      a1, 0(sp)
""")

# ( table r -- tcb )  the runnable TCB holding ticket number r (r < total)
PICKT = asm("""
    lw      a1, 0(sp)               # r
    lw      a0, 4(sp)               # table
    addi    sp, sp, 4
    li      t0, 16                  # MAXT
1:  lw      t1, 132(a0)
    li      t2, 1
    bne     t1, t2, 2f
    lw      t1, 136(a0)
    bltu    a1, t1, 3f              # r < tickets: this one
    sub     a1, a1, t1
2:  addi    a0, a0, 160
    addi    t0, t0, -1
    bnez    t0, 1b
    li      a0, 0                   # not reached when r < total
3:  sw      a0, 0(sp)
""")

# ( table -- tcb|0 )  first free TCB (index 1.., 0 is the main thread)
FINDFREE = asm("""
    lw      a0, 0(sp)
    addi    a0, a0, 160
    li      t0, 15                  # MAXT - 1
1:  lw      t1, 132(a0)
    beqz    t1, 2f
    addi    a0, a0, 160
    addi    t0, t0, -1
    bnez    t0, 1b
    li      a0, 0
2:  sw      a0, 0(sp)
""")

# ( tcb -- )  zero the 32 register slots
ZREGS = asm("""
    lw      a0, 0(sp)
    addi    sp, sp, 4
    li      t0, 32
1:  sw      zero, 0(a0)
    addi    a0, a0, 4
    addi    t0, t0, -1
    bnez    t0, 1b
""")

# ( table lo hi -- )  make every sleeping or waiting thread whose deadline
# <= now runnable; a waiting one gets its result, 0 (timed out), pushed
WAKEUP = asm("""
    lw      a1, 0(sp)               # now hi
    lw      a0, 4(sp)               # now lo
    lw      a2, 8(sp)               # table
    addi    sp, sp, 12
    li      t0, 16
1:  lw      t1, 132(a2)
    addi    t3, t1, -2
    li      t2, 2
    bgeu    t3, t2, 2f              # state not 2 or 3
    lw      t3, 152(a2)             # wake hi
    bltu    t3, a1, 3f
    bne     t3, a1, 2f
    lw      t3, 148(a2)             # wake lo
    bltu    a0, t3, 2f              # now < wake: not yet
3:  li      t2, 3
    bne     t1, t2, 4f
    lw      t3, 8(a2)               # waiting: push 0 on its data stack
    addi    t3, t3, -4
    sw      zero, 0(t3)
    sw      t3, 8(a2)
4:  li      t1, 1
    sw      t1, 132(a2)
2:  addi    a2, a2, 160
    addi    t0, t0, -1
    bnez    t0, 1b
""")

# ( table lo hi -- lo hi )  the earlier of (lo hi) and every sleeping or
# waiting thread's deadline
MINDL = asm("""
    lw      a1, 0(sp)
    lw      a0, 4(sp)
    lw      a2, 8(sp)
    addi    sp, sp, 4
    li      t0, 16
1:  lw      t1, 132(a2)
    addi    t1, t1, -2
    li      t2, 2
    bgeu    t1, t2, 2f
    lw      t3, 152(a2)
    lw      t4, 148(a2)
    bltu    t3, a1, 3f
    bne     t3, a1, 2f
    bgeu    t4, a0, 2f
3:  mv      a0, t4
    mv      a1, t3
2:  addi    a2, a2, 160
    addi    t0, t0, -1
    bnez    t0, 1b
    sw      a1, 0(sp)
    sw      a0, 4(sp)
""")

# ( table -- n )  number of sleeping or waiting threads
NWAIT = asm("""
    lw      a0, 0(sp)
    li      a1, 0
    li      t0, 16
1:  lw      t1, 132(a0)
    addi    t1, t1, -2
    li      t2, 2
    bgeu    t1, t2, 2f
    addi    a1, a1, 1
2:  addi    a0, a0, 160
    addi    t0, t0, -1
    bnez    t0, 1b
    sw      a1, 0(sp)
""")

WFI = asm("""
    wfi
""")

# ,addr emitter: pop a compile-time output cursor from the cstack and emit a
# runtime push of its address, PC-relative: `auipc t1, %hi(off); addi t1, t1,
# %lo(off)` with off = cursor - (where the auipc lands), so the image may load
# anywhere (tabernacle puts the node after itself, not at 0x80000000).  The
# compiler assembles in its own heap, so cursors are heap addresses: only their
# difference is meaningful (stdlib's `lit` would push the raw cursor).
ADDR_EMIT = asm("""
    lw      t0, 0(tp)
    addi    tp, tp, 4
    sub     t0, t0, gp              # offset from the auipc about to be emitted
    li      t6, 0x800
    add     t1, t0, t6
    srli    t1, t1, 12              # %hi (rounded so a set bit 11 in %lo is right)
    slli    t2, t1, 12
    sub     t2, t0, t2              # %lo, signed
    li      t3, 0xFFF
    and     t2, t2, t3
    slli    t4, t1, 12
    ori     t4, t4, 0x317           # auipc t1, %hi
    sw      t4, 0(gp)
    addi    gp, gp, 4
    slli    t4, t2, 20
    li      t5, 0x30313             # addi t1, t1, %lo
    or      t4, t4, t5
    sw      t4, 0(gp)
    addi    gp, gp, 4
    li      t4, 0xFFC10113          # addi sp, sp, -4
    sw      t4, 0(gp)
    addi    gp, gp, 4
    li      t4, 0x00612023          # sw t1, 0(sp)
    sw      t4, 0(gp)
    addi    gp, gp, 4
""")

DEBUG = "--debug" in sys.argv
DBG0 = "'[' lit putc dup u.x " if DEBUG else ""
DBG1 = "' ' lit putc dup u.x " if DEBUG else ""
DBG2 = "' ' lit putc dup u.x ' ' lit putc dup 80 lit + @ u.x ']' lit putc " if DEBUG else ""
out = f"""\
\\ ──────────────────────────────────────────────────────────────────────────────
\\ src/proc.fam — threads on one hart with lottery scheduling.  Needs zicsr.
\\
\\ Generated by tools/gen_proc.py: the machine-code fragments below are assembled
\\ from GNU as syntax there (disassembly after each word).  Edit the generator.
\\
\\ Model: a thread is a word body running on its own stacks in the shared address
\\ space.  A CLINT timer interrupt every QUANTUM ticks, every syscall and every
\\ PLIC interrupt enters the trap handler, which saves the running thread's
\\ registers into its TCB, switches to the kernel's stacks, runs `ktrap` (a plain
\\ fam word), and resumes whichever TCB `ktrap` left in K.  The lottery draws a
\\ random ticket from the runnable threads' total; the holder runs next.  Thread
\\ 0 is the program's original context; every other thread runs in a region of
\\ its own (RID stack, heap + data stack, loop stack), taken from the region
\\ pool at spawn and given back at exit.
\\
\\ Regions: `kinit` carves the pool from the main heap once, in three size
\\ classes whose counts it is given (128 KiB, 1 MiB, 8 MiB; the node asks for
\\ 64, 24 and 8, 96 MiB of the 128 MiB machine; the tests for 32, 4 and 1), each
\\ region aligned to its size so one PMP entry can cover it later.  `region`
\\ hands out the smallest class that fits (a larger one when that class is
\\ empty), `release` returns one.  A region is laid out like the old slot, scaled: [0,1000) RID
\\ stack, [1000,size-4000) heap up + data stack down, [size-4000,size) loop
\\ stack.  A thread's region belongs to it: `spawn` takes a 128 KiB one and
\\ `spawnin` runs the thread in a region the caller took; either way exit
\\ releases it.
\\
\\ Events: each thread has a pending-events word and a subscription mask.  Bit
\\ n (n = 1..31) is PLIC source n: the virtio-mmio slot at 0x1000n000 is source
\\ n, the UART is 10.  Bits 16 and up are free for software events (`post`).
\\ A device interrupt is a doorbell: the trap claims it, disables that source at
\\ the PLIC, and posts the bit to every thread subscribed to it; the driver
\\ drains the device, acks it, and re-enables the source (`irqon`) before it
\\ waits again.  `wait` returns at once when a subscribed event is already
\\ pending, so an interrupt that lands between a driver's last poll and its
\\ `wait` is never lost.
\\
\\ API (user side):
\\   kinit   ( n128k n1m n8m -- )   set up the table, the region pool with
\\                             that many regions of each class, the timer and
\\                             the trap vector (once)
\\   thread{{ ... }}thread       compile a thread body; at runtime pushes its address
\\   spawn   ( addr tickets -- tid )   new thread in a 128 KiB region, 0 if
\\                             the table or the pool is empty
\\   spawnin ( addr tickets base size -- tid )   new thread in that region
\\   region  ( size -- addr )  a region of at least size bytes, 0 if none
\\   release ( addr -- )       give a region back (not one a thread is using)
\\   rfree   ( class -- n )    free regions in class 0/1/2 (128 KiB/1 MiB/8 MiB)
\\   tstate  ( tid -- state )  0 free (gone), 1 runnable, 2 sleeping, 3 waiting
\\   texcode ( tid -- code )   how the thread in that slot last ended: 0 exited,
\\                             cause+1 killed (valid until the slot is reused)
\\   ktstate ( tid -- state )  tstate and post for thread 0's own use, without
\\   kpostd  ( mask tid -- )   a trap (the kernel's loop thread only)
\\   myregion ( -- base size ) the calling thread's region (0 0 for thread 0)
\\   uspawn  ( base size imgend tickets -- tid )   a USER-MODE thread running
\\                             the image at base (imgend = where its code
\\                             ends) in that region: what exec uses
\\ A thread starts with a5 = 'EXEC' (0x43455845), a6 = its region's base and
\\ a7 = the size: a program image started at the base (src/exec.fam) lays its
\\ stacks out from them in the stdlib's init; a thread body ignores them.
\\ lib/sys.fam gives a program built on its own the same words as syscalls.
\\
\\ Modes: the kernel and its own threads run in M-mode; a program exec'd from
\\ the store runs in U-mode (uspawn), and so does every thread it spawns.  A
\\ user thread is fenced by PMP, written at every switch to it: its process's
\\ image (to a page boundary: QEMU stops caching a page a PMP boundary cuts
\\ through) is read + execute, the rest of the process region read + write, its
\\ own region (for a spawned thread; the same region for the main thread) read
\\ + write, the UART page read + write, the mtime register read only; nothing
\\ else, so the kernel, other programs and the devices are out of reach, the
\\ RID stack cannot grow down into the code, and no stack can leave the region.
\\ Any other trap from a user thread (an access, alignment or illegal-
\\ instruction fault) kills that thread with a line on the UART naming the
\\ cause, the pc and the address; its region goes back.  The same fault from
\\ a kernel thread is a kernel bug and halts the machine, as before.
\\   yield   ( -- )            give up the rest of the quantum
\\   sleep   ( ticks -- )      block for at least ticks mtime ticks (10 MHz)
\\   msleep  ( ms -- )         the same in milliseconds
\\   wait    ( mask ticks -- events )  subscribe to mask; return the pending
\\                             events in it, blocking up to ticks (0 = forever)
\\                             for one; 0 on timeout
\\   post    ( mask tid -- )   add events to thread tid (software doorbell)
\\   irqon   ( irq -- )        enable PLIC source irq (priority 1) — re-arm
\\   irqoff  ( irq -- )        disable it
\\   join    ( tid -- )        yield until thread tid has exited
\\   quantum! ( ticks -- )     set the time slice (default 10 ms)
\\   texit   ( -- )            end the calling thread (what }}thread emits)
\\   getpid  ( -- tid )
\\   code{{ ... }}code           like thread{{ but without the trailing exit
\\   rtc@    ( -- lo hi )      wall clock, ns since the Unix epoch (Goldfish RTC)
\\   unix@   ( -- secs )       the same in seconds
\\   ud/     ( lo hi d -- q )  64-by-32 unsigned division (quotient fits 32 bits)
\\
\\ Sleeping and waiting threads hold no tickets.  When nothing is runnable the
\\ scheduler arms the timer for the earliest deadline and waits in `wfi`, which
\\ returns on the timer or a PLIC interrupt; when nothing is runnable, sleeping
\\ or waiting the program is finished.
\\
\\ Layout — TCB (0xA0 bytes, 16 of them):  4*n saved x_n   80 pc   84 state
\\   (0 free, 1 runnable, 2 sleeping, 3 waiting)   88 tickets   8C pid
\\   90 wait mask   94 wake lo   98 wake hi   9C pending events.
\\ Kernel block K:  0 current   4 t1 stash   8 table   C rng   10 kernel region
\\   14 ksp   18 ks8   1C ks11   20 kgp   24 quantum   28 ticks   2C IRQ events
\\   that no thread was subscribed to (claimed by the next wait that asks)
\\   30 region classes (3 x 0x18: size, base, count, free head, nfree, end)
\\   34 thread records (16 x 0x300: 0 region base, 4 size, 8 mode (1 = user),
\\   C process image base, 10 its code's end, 14 the process region's end,
\\   18 the binding of handle 0 (its length; 0 = the console), 1C the exit
\\   code (0 exited, cause+1 killed), 20..5F the binding's key, 64 a pending
\\   request (op, 68..74 four arguments, 78 the reply, 7C 1 pending 2 answered;
\\   src/ksrv.fam serves them); base 0 = no region)   38 the kernel's s10
\\   3C the slot last handed out (kfind goes round)   40 the thread the last
\\   post woke: sched runs it next, once, instead of drawing a ticket (a posted
\\   thread answers at once instead of waiting out the poster's turn)
\\   (its variable base: the trap switches to it, since a program exec'd in a
\\   region has one of its own).
\\ Region: [0,1000) RID stack (s11 down)   [1000,size-4000) heap (gp up) + data
\\   stack (sp down)   [size-4000,size) loop stack (s8 down).  The kernel's own
\\   stacks are a 128 KiB region taken at kinit.  s10 stays global so
\\   `variable` cells are shared by every thread.
\\ ──────────────────────────────────────────────────────────────────────────────

\\ ── compile-time helpers ──────────────────────────────────────────────────────

\\ ,addr  ( C: cursor -- )  emit a runtime push of the address of an output cursor
\\ taken with `here`, as auipc + addi from where it is emitted: position
\\ independent, since the image is not always loaded at 0x80000000 (tabernacle
\\ puts the node after itself).  (`lit` would push the raw compiler-heap cursor.)
:M ,addr
{ADDR_EMIT}
;

\\ code{{ ... }}code  — jump over a block; afterwards push the block's address.
\\ cstack while open: [bodyaddr patchaddr].
:I code{{  here ,j0 here cswap ;
:I }}code  jpat! ,addr ;

\\ ,texit  ( C: -- )  emit `li a7,1 ; ecall` — the exit syscall, inline.
:M ,texit
{EXIT_EMIT}
;

\\ thread{{ ... }}thread — the same, with the exit syscall appended to the body.
:I thread{{  here ,j0 here cswap ;
:I }}thread  ,texit jpat! ,addr ;

\\ ── CSR and CLINT access ──────────────────────────────────────────────────────

:M syscall    \\ ( n -- )  a7 = n; ecall
{SYSCALL}
;
:M mcause@    \\ ( -- cause )
{MCAUSE}
;
:M mtval@     \\ ( -- addr )  the faulting address
{MTVAL}
;
:M mtvec!     \\ ( addr -- )
{MTVEC}
;
:M mscr!  \\ ( addr -- )
{MSCRATCH}
;
:M int_on     \\ enable the machine timer interrupt and global interrupts
{INT_ON}
;
:M int_off
{INT_OFF}
;
:M mtime@     \\ ( -- lo hi )  consistent 64-bit read
{MTIME}
;
:M mtcmp!  \\ ( lo hi -- )
{MTIMECMP}
;
:M wfi
{WFI}
;

\\ ── kernel data ───────────────────────────────────────────────────────────────

: kblk variable ;
: K   kblk @ ;                  \\ ( -- K )
: cur K @ ;                     \\ ( -- tcb )  the thread that trapped
: ktab K 8 lit + @ ;            \\ ( -- table )
: tcb ( i -- tcb )  A0 lit * ktab + ;

\\ the trapped thread's data stack: read args, write results
: usp   cur 8 lit + @ ;                       \\ ( -- sp )
: upop  usp dup @ swap 4 lit + cur 8 lit + ! ; \\ ( -- x )
: upush usp 4 lit - dup cur 8 lit + ! ! ;     \\ ( x -- )

\\ ── table walks (asm) ─────────────────────────────────────────────────────────

:M ntickets   \\ ( table -- n )  sum of runnable tickets
{NTICKETS}
;
:M pickt      \\ ( table r -- tcb )  holder of ticket r
{PICKT}
;
:M findfree   \\ ( table -- tcb|0 )
{FINDFREE}
;
:M zregs      \\ ( tcb -- )
{ZREGS}
;
:M wakeup     \\ ( table lo hi -- )  wake sleepers and waiters due at mtime (lo hi)
{WAKEUP}
;
:M mindl      \\ ( table lo hi -- lo hi )  earlier of (lo hi) and any deadline
{MINDL}
;
:M nwait      \\ ( table -- n )  sleeping + waiting
{NWAIT}
;

\\ ── PLIC (hart 0, M-mode context 0) ──────────────────────────────────────────

: claim    ( -- irq )   0C200004 lit @ ;
: complete ( irq -- )   0C200004 lit ! ;
: plicen   ( irq -- addr bit )  dup 5 lit rshift 4 lit * 0C002000 lit + swap 1F lit and 1 lit swap lshift ;
: plicoff  ( irq -- )   plicen invert over @ and swap ! ;
\\ enable first, priority last: QEMU's PLIC only re-evaluates the hart's line on
\\ a priority or threshold write, so a source already asserted would otherwise
\\ not interrupt until something else changed
: plicon   ( irq -- )   dup plicen over @ or swap !  4 lit * 0C000000 lit + 1 lit swap ! ;

\\ ── events ────────────────────────────────────────────────────────────────────

: tpush ( x tcb -- )  8 lit + dup @ 4 lit - dup rot ! ! ;   \\ onto its data stack

\\ a waiting thread whose pending events meet its mask gets them and runs
: twake ( tcb -- )
    dup 84 lit + @ 3 lit = if
        dup 9C lit + @ over 90 lit + @ and ?dup if      \\ tcb hit
            2dup swap 9C lit + dup @ rot xor swap !      \\ events ^= hit
            over tpush
            1 lit over 84 lit + !
            dup K 40 lit + !                             \\ run it next
        then
    then drop ;
: tpost ( mask tcb -- )  swap over 9C lit + dup @ rot or swap ! twake ;

\\ an interrupt: to every live thread subscribed to any of its bits; bits
\\ nobody wanted are kept in K for the next wait that asks for them
: ktaken variable ;
: kpost ( mask -- )
    0 lit ktaken !
    dup 10 lit 0 lit do
        i tcb dup 84 lit + @ if
            2dup 90 lit + @ and ?dup if
                dup ktaken @ or ktaken !
                swap tpost
            else drop then
        else drop then
    loop drop
    ktaken @ invert and
    K 2C lit + dup @ rot or swap ! ;

\\ claim every pending PLIC interrupt: disable the source (the driver re-enables
\\ it once it has drained the device) and post its bit
: irq! ( -- )
    begin claim ?dup if dup plicoff 1 lit over lshift kpost complete 0 lit else -1 lit then until ;

\\ ── scheduler ─────────────────────────────────────────────────────────────────

\\ xorshift32 (seeded from mtime in kinit)
: rand ( -- u )
    K C lit + @
    dup D lit lshift xor
    dup 11 lit rshift xor
    dup 5 lit lshift xor
    dup K C lit + ! ;

\\ arm the timer: the sooner of QUANTUM ticks from now and the earliest wake-up
\\ (64-bit add on the mtime pair).  Writing mtimecmp also clears a pending MTIP.
: arm ( -- )
    mtime@ swap K 24 lit + @ +          \\ hi lo'
    dup K 24 lit + @ u< if swap 1 lit + swap then
    swap ktab -rot mindl mtcmp! ;

\\ pick the next thread into K.  Nothing runnable: wait in wfi for the earliest
\\ deadline or a device interrupt (both stay enabled in mie, so wfi returns on
\\ MTIP/MEIP even with mstatus.MIE clear; the PLIC is then polled by hand since
\\ no trap can be taken here).  Nothing runnable, sleeping or waiting: done.
: sched ( -- )
    begin
        ktab mtime@ wakeup
        ktab ntickets dup 0= if
            drop
            ktab nwait 0= if bye then
            ktab -1 lit -1 lit mindl mtcmp! wfi irq!
            0 lit
        else
            K 40 lit + @ ?dup if 0 lit K 40 lit + ! dup 84 lit + @ 1 lit = if K ! drop -1 lit else drop
                rand swap % ktab swap pickt {DBG2}K ! -1 lit then
            else
                rand swap %
                ktab swap pickt {DBG2}K !
                -1 lit
            then
        then
    until ;

\\ the kernel's own thread (0) reading and posting without a trap: a syscall
\\ costs 13 us under QEMU and the loop made three or four a turn
: ktstate ( tid -- state )  F lit and tcb 84 lit + @ ;
: kpostd  ( mask tid -- )   int_off F lit and tcb tpost int_on ;

: khalt  begin wfi 0 lit until ;

\\ ── regions ───────────────────────────────────────────────────────────────────
\\ A free region's first word links to the next free one (the list is pushed in
\\ reverse, so the lowest free region of a class is handed out first).  kregion
\\ and krelease are the kernel's own (inside the trap, or before it is armed);
\\ threads use the syscalls region and release.

: rcls ( c -- rec )  18 lit * K 30 lit + @ + ;
: rrec ( tid -- rec )  300 lit * K 34 lit + @ + ;
: rfree ( c -- n )  rcls 10 lit + @ ;
: rpush ( addr c -- )  rcls  dup C lit + @ 2 lit pick !  swap over C lit + !  10 lit + dup @ 1 lit + swap ! ;
: rpop ( c -- addr|0 )
    rcls dup C lit + @ ?dup if
        dup @ 2 lit pick C lit + !  over 10 lit + dup @ 1 lit - swap !  nip
    else drop 0 lit then ;
: kregion ( size -- addr|0 )
    0 lit swap 3 lit 0 lit do
        over 0= if dup i rcls @ u> 0= if i rpop rot drop swap then then
    loop drop ;
: rclsof ( addr -- c|-1 )
    -1 lit 3 lit 0 lit do
        over i rcls 4 lit + @ -  i rcls 14 lit + @ i rcls 4 lit + @ -  u< if drop i then
    loop nip ;
: krelease ( addr -- )
    dup rclsof dup 0< if "proc: release: not a region\\n" puts khalt then
    over over rcls @ 1 lit - and if "proc: release: not a region's base\\n" puts khalt then
    rpush ;
\\ rpinit ( n128k n1m n8m -- )  the pool from the main heap, the base aligned to
\\ 8 MiB, the largest class first so every region is aligned to its size
: rpinit
    48 lit alloc K 30 lit + !
    3000 lit alloc K 34 lit + !  K 34 lit + @ C00 lit 0 lit do 0 lit over i 2 lit lshift + ! loop drop
    1 lit 0 lit rrec 80 lit + !  2F lit 0 lit rrec 84 lit + c!                       \\ thread 0 works at "/"
    800000 lit 2 lit rcls !  2 lit rcls 8 lit + !
    100000 lit 1 lit rcls !  1 lit rcls 8 lit + !
    20000 lit 0 lit rcls !   0 lit rcls 8 lit + !
    0 lit 3 lit 0 lit do i rcls @ i rcls 8 lit + @ * + loop
    7FFFFF lit + alloc ?dup 0= if "proc: no room for the region pool\\n" puts khalt then
    7FFFFF lit + FF800000 lit and
    3 lit 0 lit do                                                     \\ classes 2, 1, 0 in memory order
        2 lit i - rcls                                                 \\ base rec
        2dup 4 lit + !  0 lit over C lit + !  0 lit over 10 lit + !
        dup @ over 8 lit + @ * 2 lit pick + over 14 lit + !            \\ end
        dup 8 lit + @ 0 lit do                                         \\ push from the top down
            dup 14 lit + @ i 1 lit + 2 lit pick @ * -  2 lit j - rpush
        loop
        14 lit + @ swap drop                                           \\ the next class starts at end
    loop drop ;

\\ ── syscalls ──────────────────────────────────────────────────────────────────
\\ 0 yield   1 exit   2 spawn ( addr tickets -- tid )   3 getpid ( -- tid )
\\ 4 sleep ( ticks -- )   5 wait ( mask ticks -- events )   6 post ( mask tid -- )
\\ 7 spawnin ( addr tickets base size -- tid )   8 region ( size -- addr )
\\ 9 release ( addr -- )   A tstate ( tid -- state )   B myregion ( -- base size )
\\ C uspawn ( base size imgend tickets -- tid )   D request ( op a b c d -- events )
\\ E reply ( -- r )   F texcode ( tid -- code )

\\ kfind ( -- tcb|0 )  a free slot, round robin from the last one handed out
\\ (K+3C), so a slot that just died is not reused while 14 others are free:
\\ a parent that polls its children by tid sees them go before the number
\\ means someone else
: kfind
    0 lit 11 lit 1 lit do                   \\ 16 steps: every slot but the one it starts after, then that one too
        dup 0= if drop K 3C lit + @ i + F lit and
            dup 0= if drop 0 lit else dup tcb 84 lit + @ if drop 0 lit else dup K 3C lit + ! tcb then then
        then
    loop ;

\\ build a fresh context in tcb for the body at addr, in the region of tcb's rrec
: rgb variable ;  : rgt variable ;  : rgr variable ;  : ust variable ;  : usi variable ;
: tinit ( tickets addr tcb -- )
    dup zregs                           \\ tickets addr tcb
    dup 8C lit + @ rrec dup @ rgb ! 4 lit + @ rgb @ + rgt !
    rgb @ 1000 lit + over 6C lit + !    \\ s11 = base + 0x1000 (RID top)
    rgb @ 1000 lit + over C lit + !     \\ gp  = base + 0x1000 (heap base)
    rgt @ 4000 lit - over 8 lit + !     \\ sp  = top - 0x4000 (data stack top)
    rgt @ over 60 lit + !               \\ s8  = top (loop stack top)
    cur 68 lit + @ over 68 lit + !      \\ s10 = the global RID floor / var base
    43455845 lit over 3C lit + !        \\ a5 = 'EXEC', a6 = base, a7 = size: the handoff
    rgb @ over 40 lit + !
    rgt @ rgb @ - over 44 lit + !
    dup 1 lit swap 84 lit + !           \\ state = runnable
    dup 0 lit swap 90 lit + !           \\ no subscription
    dup 0 lit swap 9C lit + !           \\ no pending events
    swap over 80 lit + !                \\ pc = addr          ( tickets tcb )
    88 lit + ! ;                        \\ tickets

: spid variable ;
\\ tspawn ( tickets addr base size -- tid )  a thread in that region; 0 (and the region untouched) when the table is full
: tspawn
    kfind dup 0= if drop 2drop 2drop 0 lit else
        dup 8C lit + @ rrec rgr !
        -rot rgr @ 4 lit + ! rgr @ !    \\ tickets addr tcb
        cur 8C lit + @ rrec 8 lit + rgr @ 8 lit + 58 lit mcopy   \\ the spawner's mode, process and binding
        cur 8C lit + @ rrec 80 lit + rgr @ 80 lit + 204 lit mcopy  \\ and its working directory
        0 lit rgr @ 1C lit + !  0 lit rgr @ 7C lit + !
        dup 8C lit + @ spid !
        tinit spid @
    then ;
: sysspawn ( -- )
    upop upop                           \\ tickets addr
    20000 lit kregion ?dup if
        dup rgb !  20000 lit tspawn dup 0= if rgb @ krelease then upush
    else 2drop 0 lit upush then ;
: sysspwin ( -- )
    upop rgt ! upop rgb ! upop upop     \\ tickets addr
    rgb @ rgt @ tspawn upush ;

\\ tgone ( code -- )  the thread ends: its exit code kept, the region back, the
\\ slot free; when handle 0 was bound to a key the loop thread (0) is posted
\\ bit 16 so it flushes what the thread had buffered (src/ksrv.fam).  The
\\ binding stays for that flush.
: tgone
    cur 8C lit + @ rrec dup 1C lit + rot swap !
    0 lit cur 84 lit + !
    dup @ ?dup if krelease then
    6 lit 0 lit do 0 lit over i 2 lit lshift + ! loop
    dup 0 lit swap 7C lit + !
    18 lit + @ 0= 0=  cur 0 lit tcb <>  and if 10000 lit 0 lit tcb tpost then ;
: sysexit ( -- )  0 lit tgone ;
\\ a user-mode thread for the image at base: its process is that region
: sysuspwn ( -- )
    upop ust ! upop usi ! upop rgt ! upop rgb !
    ust @ rgb @ rgb @ rgt @ tspawn
    dup if dup rrec 1 lit over 8 lit + !  rgb @ over C lit + !  usi @ over 10 lit + !  rgb @ rgt @ + swap 14 lit + ! then
    upush ;
: sysregn ( -- )  upop kregion upush ;
: sysrels ( -- )  upop krelease ;
: systst  ( -- )  upop F lit and tcb 84 lit + @ upush ;
: sysmyrg ( -- )  cur 8C lit + @ rrec dup @ upush 4 lit + @ upush ;
: sysgpid ( -- )  cur 8C lit + @ upush ;

\\ deadline = mtime + ticks (64-bit) into the current TCB
: deadlin! ( ticks -- )
    mtime@                              \\ t lo hi
    rot rot                             \\ hi t lo
    over +                              \\ hi t lo'
    tuck swap u<                        \\ hi lo' carry(-1|0)
    rot swap -                          \\ lo' hi+carry
    cur 98 lit + !  cur 94 lit + ! ;

\\ state = sleeping until the deadline.  0 ticks is a yield.
: syssleep ( -- )
    upop ?dup if deadlin! 2 lit cur 84 lit + ! then ;

\\ subscribe to mask.  Something pending already: hand it over and carry on.
\\ Else state = waiting until an event (twake) or the deadline (wakeup pushes 0);
\\ 0 ticks = no deadline.
: syswait ( -- )
    upop upop                           \\ ticks mask
    dup cur 90 lit + !
    K 2C lit + @ over and ?dup if       \\ unclaimed interrupts: take them
        dup K 2C lit + dup @ rot xor swap !
        cur tpost
    then
    cur 9C lit + @ and ?dup if          \\ ticks hit
        dup cur 9C lit + dup @ rot xor swap !
        upush drop
    else
        ?dup if deadlin! else -1 lit cur 94 lit + ! -1 lit cur 98 lit + ! then
        3 lit cur 84 lit + !
    then ;

: syspost ( -- )
    upop tcb upop over 84 lit + @ if swap tpost else 2drop then ;

\\ a request to the loop thread: five words into the record, bit 16 to thread
\\ 0, then the caller waits for bit 17 as `wait` would (the events land on
\\ its stack; lib/sys.fam drops them and reads the reply)
: sysreq ( -- )
    cur 8C lit + @ rrec
    upop over 74 lit + !  upop over 70 lit + !  upop over 6C lit + !  upop over 68 lit + !  upop over 64 lit + !
    1 lit swap 7C lit + !
    10000 lit 0 lit tcb tpost
    20000 lit upush 0 lit upush syswait ;
: sysrep  ( -- )  cur 8C lit + @ rrec dup 78 lit + @ upush 0 lit swap 7C lit + ! ;
: sysxcod ( -- )  upop F lit and rrec 1C lit + @ upush ;

: syscall! ( -- )
    cur 80 lit + dup @ 4 lit + swap !   \\ resume after the ecall
    cur 44 lit + @                      \\ a7
    dup 0= if drop else
    dup 1 lit = if drop sysexit else
    dup 2 lit = if drop sysspawn else
    dup 3 lit = if drop sysgpid else
    dup 4 lit = if drop syssleep else
    dup 5 lit = if drop syswait else
    dup 6 lit = if drop syspost else
    dup 7 lit = if drop sysspwin else
    dup 8 lit = if drop sysregn else
    dup 9 lit = if drop sysrels else
    dup A lit = if drop systst else
    dup B lit = if drop sysmyrg else
    dup C lit = if drop sysuspwn else
    dup D lit = if drop sysreq else
    dup E lit = if drop sysrep else
    dup F lit = if drop sysxcod else
    drop then then then then then then then then then then then then then then then then ;

\\ the trap entry: everything between the two asm pieces is ordinary fam running
\\ on the kernel's stacks with interrupts masked.
\\ tkill ( cause -- )  a user thread faulted: say so and end it
: tkill
    "proc: thread " puts cur 8C lit + @ u. " killed: cause " puts dup u. " at " puts cur 80 lit + @ u.x
    ", address " puts mtval@ u.x '\\n' lit putc
    1 lit + tgone ;

: ktrap ( -- )
    mcause@ {DBG0}
    dup 80000007 lit = if drop K 28 lit + dup @ 1 lit + swap ! else
    dup 8000000B lit = if drop irq! else
    dup B lit = if drop syscall! else
    dup 8 lit = if drop syscall! else
    cur 8C lit + @ rrec 8 lit + @ if tkill else
        "proc: unexpected trap " puts u.x '\\n' lit putc khalt
    then then then then then
    sched arm ;


\\ ── user words ────────────────────────────────────────────────────────────────

: yield   ( -- )               0 lit syscall ;
: texit   ( -- )               1 lit syscall ;
: spawn   ( addr tickets -- tid ) 2 lit syscall ;
: spawnin ( addr tickets base size -- tid ) 7 lit syscall ;
: region  ( size -- addr )     8 lit syscall ;
: release ( addr -- )          9 lit syscall ;
: tstate  ( tid -- state )     A lit syscall ;
: myregion ( -- base size )    B lit syscall ;
: uspawn  ( base size imgend tickets -- tid ) C lit syscall ;
: texcode ( tid -- code )      F lit syscall ;
: getpid  ( -- tid )           3 lit syscall ;
: sleep   ( ticks -- )         4 lit syscall ;
: msleep  ( ms -- )            2710 lit * sleep ;     \\ 10000 ticks per ms
: wait    ( mask ticks -- events ) 5 lit syscall ;
: post    ( mask tid -- )      6 lit syscall ;
\\ the PLIC enable word is shared with the trap's plicoff: update it masked
: irqon   ( irq -- )           int_off plicon int_on ;
: irqoff  ( irq -- )           int_off plicoff int_on ;
: join    ( tid -- )           begin dup tcb 84 lit + @ 0= dup 0= if yield then until drop ;
                                                      \\ wait until the slot is free
: quantum! ( ticks -- )        K 24 lit + ! ;         \\ takes effect at the next arm

\\ ── clock ─────────────────────────────────────────────────────────────────────

\\ rtc@ ( -- lo hi )  wall clock: nanoseconds since the Unix epoch, from the virt
\\ board's Goldfish RTC at 0x101000 (reading TIME_LOW latches TIME_HIGH).  No
\\ trap: everything runs in M-mode, so a syscall would only add its cost.
: rtc@
{RTC}
;

\\ ud/ ( lo hi d -- q )  unsigned 64-by-32 division, shift-and-subtract (a
\\ remainder bit carried out of the shift always clears the divisor); the
\\ quotient must fit 32 bits (hi < d).  What the clock words need, and what
\\ anything scaling a 64-bit tick count needs.
: ud/
{UDIV}
;

: unix@ ( -- secs )            rtc@ 3B9ACA00 lit ud/ ;   \\ seconds since the epoch

\\ ── kinit ─────────────────────────────────────────────────────────────────────

: kinit ( n128k n1m n8m -- )
    \\ K block, the table, the region pool
    48 lit alloc kblk !
    0 lit K 40 lit + !                  \\ nobody woken yet
    0 lit K 28 lit + !                  \\ ticks = 0
    0 lit K 2C lit + !                  \\ no unclaimed interrupts
    0 lit K 3C lit + !                  \\ slots are handed out from 1
    A00 lit alloc K 8 lit + !           \\ 16 TCBs, zeroed, pid = index
    10 lit 0 lit do
        i tcb dup
        A0 lit 0 lit do 0 lit over i + ! loop
        i swap 8C lit + ! drop
    loop
    rpinit                              \\ ( n128k n1m n8m -- )
    \\ the kernel's own stacks: a 128 KiB region
    20000 lit kregion dup K 10 lit + !
    1301C1FF , 2320A101 ,                \\ addi sp,sp,-4 ; sw s10,0(sp): push s10
    K 38 lit + !                        \\ the kernel's variable base, for the trap
    dup 1000 lit + K 1C lit + !         \\ ks11
    dup 1000 lit + K 20 lit + !         \\ kgp
    dup 1C000 lit + K 14 lit + !        \\ ksp
    20000 lit + K 18 lit + !            \\ ks8
    \\ thread 0 = this context
    0 lit tcb dup K !
    dup 1 lit swap 84 lit + !           \\ runnable
    A lit swap 88 lit + !               \\ 10 tickets (pid 0 already set)
    \\ scheduler parameters
    186A0 lit K 24 lit + !              \\ quantum = 100000 ticks = 10 ms
    mtime@ drop 1 lit or K C lit + !    \\ rng seed (never 0)
    0 lit 0C200000 lit !                \\ PLIC threshold 0: every enabled source
    \\ trap vector, then go
    K mscr!
    code{{
{SAVE}
    ktrap
{RESTORE}
    }}code mtvec!
    arm int_on ;

\\ ── tests ─────────────────────────────────────────────────────────────────────
\\ ./tools/fam --test src/proc.fam   (lib/build.fam makes the block vanish in a
\\ normal build).  The suite runs on thread 0 after `kinit`, so the tests are
\\ ordered: every test that spawns joins what it spawned and leaves the table as
\\ it found it.  Words defined inside a body are ordinary definitions (the tests
\\ run as straight-line code).  Timing tests use `_now` from lib/test.fam.
\\ `0=` and friends yield -1 for true.

Test {{
	kinit {{
		20 lit 4 lit 1 lit kinit
		getpid 0 lit asrt_eq
		cur 0 lit tcb asrt_eq
		0 lit tcb 84 lit + @ 1 lit asrt_eq         \\ thread 0 runnable
		0 lit tcb 88 lit + @ A lit asrt_eq         \\ 10 tickets
		K 24 lit + @ 186A0 lit asrt_eq             \\ 10 ms quantum
		ktab ntickets A lit asrt_eq
		ktab nwait 0 lit asrt_eq
		ktab findfree 1 lit tcb asrt_eq            \\ slot 1 is the first free
		K 1C lit + @ K 10 lit + @ 1000 lit + asrt_eq
		K 14 lit + @ K 10 lit + @ 1C000 lit + asrt_eq
	}}
	\\ the pool: counts, alignment, the smallest class that fits, spill, release
	regions {{
		: rg variable ;  : rg2 variable ;  : xr0 variable ;
		0 lit rfree 1F lit asrt_eq  1 lit rfree 4 lit asrt_eq  2 lit rfree 1 lit asrt_eq
		K 10 lit + @ 1FFFF lit and 0 lit asrt_eq
		K 10 lit + @ rclsof 0 lit asrt_eq
		1 lit region dup rg ! 1FFFF lit and 0 lit asrt_eq  0 lit rfree 1E lit asrt_eq
		rg @ rclsof 0 lit asrt_eq
		20001 lit region dup rg2 ! FFFFF lit and 0 lit asrt_eq  1 lit rfree 3 lit asrt_eq
		rg2 @ rclsof 1 lit asrt_eq  rg2 @ 20000 lit + rclsof 1 lit asrt_eq
		rg2 @ release  1 lit rfree 4 lit asrt_eq
		800000 lit region dup rg2 ! 7FFFFF lit and 0 lit asrt_eq  2 lit rfree 0 lit asrt_eq
		rg2 @ release  2 lit rfree 1 lit asrt_eq
		800001 lit region 0 lit asrt_eq
		rg @ release  0 lit rfree 1F lit asrt_eq
		1E lit 0 lit do 20000 lit region drop loop  0 lit rfree 1 lit asrt_eq        \\ all but the last
		20000 lit region drop  0 lit rfree 0 lit asrt_eq
		20000 lit region dup rg ! FFFFF lit and 0 lit asrt_eq  1 lit rfree 3 lit asrt_eq   \\ spilled to 1 MiB
		rg @ release  1 lit rfree 4 lit asrt_eq
		K 10 lit + @ 1F lit 0 lit do 20000 lit + dup release loop drop  0 lit rfree 1F lit asrt_eq
		K 30 lit + @ 14 lit + @ rclsof -1 lit asrt_eq
	}}
	table {{
		3 lit tcb 0 lit tcb - 1E0 lit asrt_eq
		10 lit 0 lit do
			i tcb 8C lit + @ i asrt_eq             \\ pid = index
			i tcb 84 lit + @ i 0= 1 lit and asrt_eq          \\ only 0 is live
		loop
	}}
	rand {{
		K C lit + @                                \\ save the seed
		1 lit K C lit + !
		rand 42021 lit asrt_eq
		rand 4080601 lit asrt_eq
		rand 9DCCA8C5 lit asrt_eq
		K C lit + !
	}}
	clock {{
		\\ Goldfish RTC: ns since the Unix epoch; unix@ is seconds
		rtc@ 0 lit u> assert drop                    \\ hi word nonzero: past 1970
		unix@ dup 6955B900 lit u> assert             \\ after 2026-01-01
		7FFFFFFF lit u< assert                       \\ before 2038: a sane host clock
		rtc@ drop A lit msleep rtc@ drop swap -      \\ 10 ms: 1e7 .. 1e9 ns
		dup 989680 lit u< 0= assert  3B9ACA00 lit u< assert
		\\ ud/: 64-by-32 with a 32-bit quotient
		0 lit 1 lit 4 lit ud/ 40000000 lit asrt_eq                     \\ 2^32 / 4
		5 lit 0 lit 2 lit ud/ 2 lit asrt_eq
		0 lit 1 lit 3B9ACA00 lit ud/ 4 lit asrt_eq                     \\ 2^32 ns = 4 s
		FFFFFFFF lit FFFFFFFE lit FFFFFFFF lit ud/ FFFFFFFF lit asrt_eq \\ (2^64-2^32-1)/(2^32-1)
	}}
	lottery {{
		int_off
		ktab 0 lit pickt 0 lit tcb asrt_eq
		ktab 9 lit pickt 0 lit tcb asrt_eq
		ktab A lit pickt 0 lit asrt_eq             \\ no holder of ticket 10
		\\ a second runnable thread with 3 tickets
		3 lit 5 lit tcb 88 lit + !  1 lit 5 lit tcb 84 lit + !
		ktab ntickets D lit asrt_eq
		ktab 9 lit pickt 0 lit tcb asrt_eq
		ktab A lit pickt 5 lit tcb asrt_eq
		ktab C lit pickt 5 lit tcb asrt_eq
		ktab D lit pickt 0 lit asrt_eq
		ktab findfree 1 lit tcb asrt_eq
		0 lit 5 lit tcb 84 lit + !  0 lit 5 lit tcb 88 lit + !
		int_on
	}}
	sleepers {{
		int_off
		\\ thread 5 asleep until (lo FFFFFFFF, hi 7FFFFFFF)
		2 lit 5 lit tcb 84 lit + !
		-1 lit 5 lit tcb 94 lit + !  7FFFFFFF lit 5 lit tcb 98 lit + !
		ktab nwait 1 lit asrt_eq
		ktab ntickets A lit asrt_eq                \\ sleeping holds no tickets
		ktab 0 lit pickt 0 lit tcb asrt_eq
		ktab -1 lit -1 lit mindl 7FFFFFFF lit asrt_eq -1 lit asrt_eq
		ktab 0 lit 0 lit mindl 0 lit asrt_eq 0 lit asrt_eq
		ktab 5 lit 7FFFFFFF lit mindl 7FFFFFFF lit asrt_eq 5 lit asrt_eq
		ktab 0 lit 80000000 lit mindl 7FFFFFFF lit asrt_eq -1 lit asrt_eq
		ktab -2 lit 7FFFFFFF lit wakeup            \\ one tick early: still asleep
		5 lit tcb 84 lit + @ 2 lit asrt_eq
		ktab -1 lit 7FFFFFFF lit wakeup            \\ due now: runnable
		5 lit tcb 84 lit + @ 1 lit asrt_eq
		0 lit 5 lit tcb 84 lit + !
		int_on
	}}
	tinit {{
		: tsp variable ;
		int_off
		100000 lit region F lit rrec !  100000 lit F lit rrec 4 lit + !
		thread{{ }}thread 3 lit swap F lit tcb tinit
		F lit tcb 84 lit + @ 1 lit asrt_eq
		F lit tcb 88 lit + @ 3 lit asrt_eq
		F lit tcb 8C lit + @ F lit asrt_eq
		F lit tcb 8 lit + @ F lit rrec @ FC000 lit + asrt_eq    \\ sp
		F lit tcb C lit + @ F lit rrec @ 1000 lit + asrt_eq     \\ gp
		F lit tcb 6C lit + @ F lit rrec @ 1000 lit + asrt_eq    \\ s11
		F lit tcb 60 lit + @ F lit rrec @ 100000 lit + asrt_eq  \\ s8
		F lit tcb 68 lit + @ 0 lit tcb 68 lit + @ asrt_eq       \\ s10 shared
		F lit tcb 3C lit + @ 43455845 lit asrt_eq               \\ a5 a6 a7: the handoff
		F lit tcb 40 lit + @ F lit rrec @ asrt_eq  F lit tcb 44 lit + @ 100000 lit asrt_eq
		F lit tcb 4 lit + @ 0 lit asrt_eq                       \\ ra zeroed
		0 lit F lit tcb 84 lit + !
		F lit rrec @ release  0 lit F lit rrec !
		int_on
	}}
	spawn {{
		: cnt variable ;
		: tpid variable ;
		0 lit cnt !
		thread{{ getpid tpid ! 1 lit cnt ! }}thread 1 lit spawn
		dup 1 lit asrt_eq
		join
		cnt @ 1 lit asrt_eq
		tpid @ 1 lit asrt_eq
		1 lit tcb 84 lit + @ 0 lit asrt_eq
		ktab ntickets A lit asrt_eq
		ktab findfree 1 lit tcb asrt_eq
		0 lit rfree 1F lit asrt_eq                 \\ the thread's region came back
		1 lit rrec @ 0 lit asrt_eq
	}}
	stacks {{
		: tgp variable ;
		: mgp variable ;
		: tbase variable ;
		0 lit alloc mgp !
		thread{{ sp@ tsp !  10 lit alloc tgp !  getpid rrec @ tbase ! }}thread 1 lit spawn join
		tbase @ 1FFFF lit and 0 lit asrt_eq
		tsp @ tbase @ 1000 lit + u> assert
		tsp @ tbase @ 1C000 lit + 4 lit + u< assert
		tgp @ tbase @ 1000 lit + asrt_eq
		0 lit alloc mgp @ asrt_eq                  \\ thread allocs do not move ours
	}}
	\\ user mode: a hand-made image that writes into its own region and exits; one that
	\\ writes a kernel variable and is killed for it, the variable untouched
	umode {{
		: umb variable ;  : umv variable ;
		0 lit rfree xr0 !  20000 lit region umb !
		11082023 lit umb @ !  00100893 lit umb @ 4 lit + !  00000073 lit umb @ 8 lit + !       \\ sw a6,256(a6); li a7,1; ecall
		0 lit umb @ 100 lit + !
		umb @ 20000 lit umb @ C lit + 5 lit uspawn dup 0 lit <> assert join
		umb @ 100 lit + @ umb @ asrt_eq  0 lit rfree xr0 @ asrt_eq
		20000 lit region umb !  12345678 lit umv !
		umv 800 lit + FFFFF000 lit and 2B7 lit or umb @ !                                    \\ lui t0,%hi(umv)
		umv FFF lit and 14 lit lshift 28293 lit or umb @ 4 lit + !                            \\ addi t0,t0,%lo(umv)
		0102A023 lit umb @ 8 lit + !  00100893 lit umb @ C lit + !  00000073 lit umb @ 10 lit + !   \\ sw a6,0(t0); li a7,1; ecall
		umb @ 20000 lit umb @ 14 lit + 5 lit uspawn dup 0 lit <> assert dup join
		dup tstate 0 lit asrt_eq  texcode 8 lit asrt_eq  umv @ 12345678 lit asrt_eq  0 lit rfree xr0 @ asrt_eq
	}}
	\\ a thread in a 1 MiB region the caller took: its stacks are laid out in it, exit gives it back
	spawnin {{
		: rsz variable ;  : stid variable ;
		100000 lit region rg !
		thread{{ sp@ tsp !  myregion rsz ! tbase ! }}thread 1 lit rg @ 100000 lit spawnin
		dup 0 lit <> assert  dup stid !  join
		tbase @ rg @ asrt_eq  rsz @ 100000 lit asrt_eq  myregion 0 lit asrt_eq 0 lit asrt_eq
		stid @ tstate 0 lit asrt_eq  0 lit tstate 1 lit asrt_eq  stid @ texcode 0 lit asrt_eq
		tsp @ rg @ FC000 lit + 4 lit + u< assert  tsp @ rg @ F0000 lit + u> assert
		1 lit rfree 4 lit asrt_eq  stid @ rrec @ 0 lit asrt_eq
		\\ slots go round: the next spawn gets the slot after this one
		thread{{ }}thread 1 lit spawn dup stid @ 1 lit + F lit and asrt_eq join
		0 lit rfree 1F lit asrt_eq
		\\ the pool empty: spawn fails cleanly and the table stays free
		1F lit 0 lit do 20000 lit region drop loop  4 lit 0 lit do 100000 lit region drop loop  1 lit 0 lit do 800000 lit region drop loop
		thread{{ }}thread 1 lit spawn 0 lit asrt_eq  ktab findfree 1 lit tcb asrt_eq
		K 10 lit + @ 1F lit 0 lit do 20000 lit + dup release loop drop
		1 lit rcls 4 lit + @ 4 lit 0 lit do dup release 100000 lit + loop drop
		2 lit rcls 4 lit + @ 1 lit 0 lit do dup release 800000 lit + loop drop
		0 lit rfree 1F lit asrt_eq  1 lit rfree 4 lit asrt_eq  2 lit rfree 1 lit asrt_eq
	}}
	yield {{
		yield
		0 lit sleep
		getpid 0 lit asrt_eq
	}}
	tabfull {{
		: flag variable ;
		0 lit flag !  0 lit K 3C lit + !            \\ slots from 1 again
		10 lit 1 lit do
			thread{{ begin yield flag @ until }}thread 1 lit spawn i asrt_eq
		loop
		thread{{ }}thread 1 lit spawn 0 lit asrt_eq  \\ 16th: table full
		ktab ntickets 19 lit asrt_eq
		ktab findfree 0 lit asrt_eq
		1 lit flag !
		10 lit 1 lit do i join loop
		ktab ntickets A lit asrt_eq
		ktab findfree 1 lit tcb asrt_eq
	}}
	preempt {{
		: ticks K 28 lit + @ ;
		0 lit flag !  0 lit cnt !
		thread{{ begin cnt @ 1 lit + cnt ! flag @ until }}thread 1E lit spawn
		ticks _now
		begin dup _now swap - 1E8480 lit u< 0= until drop     \\ spin 200 ms, no syscalls
		cnt @ 0 lit u> assert                      \\ the spinner ran: we were preempted
		ticks swap - 5 lit u> assert               \\ timer traps happened
		1 lit flag !  join
	}}
	quantum {{
		0 lit flag !  0 lit cnt !
		3E8 lit quantum!                           \\ 1000 ticks = 0.1 ms
		thread{{ begin cnt @ 1 lit + cnt ! flag @ until }}thread A lit spawn
		ticks _now
		begin dup _now swap - 186A0 lit u< 0= until drop      \\ 10 ms
		ticks swap - 32 lit u> assert              \\ > 50 traps in 10 ms
		186A0 lit quantum!
		1 lit flag !  join
	}}
	sleep {{
		_now 32 lit msleep _now swap -             \\ 50 ms
		dup 7A120 lit u< 0= assert
		4C4B40 lit u< assert
		0 lit tcb 84 lit + @ 1 lit asrt_eq
	}}
	idle {{
		ticks 64 lit msleep ticks swap -           \\ 100 ms with nothing runnable
		3 lit u< assert                            \\ wfi until the wake-up, no tick storm
	}}
	sleeping {{
		thread{{ C8 lit msleep }}thread 7 lit spawn
		A lit msleep
		dup tcb 84 lit + @ 2 lit asrt_eq
		ktab nwait 1 lit asrt_eq
		ktab ntickets A lit asrt_eq
		join
		ktab nwait 0 lit asrt_eq
	}}
	wakeorder {{
		: wlog variable ;
		: wlogn variable ;
		: wlog! ( pid -- )  wlogn @ 1 lit + dup wlogn ! wlog + c! ;
		0 lit wlogn !  0 lit wlog !  0 lit K 3C lit + !            \\ slots from 1 again
		thread{{ 1E lit msleep getpid wlog! }}thread 1 lit spawn
		thread{{ A lit msleep getpid wlog! }}thread 1 lit spawn
		thread{{ 14 lit msleep getpid wlog! }}thread 1 lit spawn
		join join join
		wlogn @ 3 lit asrt_eq
		wlog 1 lit + c@ 2 lit asrt_eq
		wlog 2 lit + c@ 3 lit asrt_eq
		wlog 3 lit + c@ 1 lit asrt_eq
	}}
	periodic {{
		\\ a sleeper that wakes every 10 ms beside two busy threads (one of them
		\\ yielding), with the thread body in a word and a do-loop on the thread's
		\\ own loop stack: the shape of the old src/proc_demo.fam
		: pcnt variable ;
		: ptick ( -- tid )
			thread{{ A lit 0 lit do pcnt @ 1 lit + pcnt ! A lit msleep loop }}thread 64 lit spawn ;
		0 lit flag !  0 lit pcnt !
		thread{{ begin flag @ until }}thread 4 lit spawn
		thread{{ begin yield flag @ until }}thread 2 lit spawn
		_now ptick join _now swap -                \\ 10 x 10 ms
		dup F4240 lit u< 0= assert                 \\ >= 100 ms
		4C4B40 lit u< assert                       \\ < 500 ms: wake-ups are not starved
		pcnt @ A lit asrt_eq
		1 lit flag !  join join
	}}
	waitto {{
		\\ no event: wait times out at the deadline and returns 0
		_now 0 lit 186A0 lit wait 0 lit asrt_eq _now swap -    \\ 10 ms
		dup 186A0 lit u< 0= assert  4C4B40 lit u< assert
		0 lit tcb 84 lit + @ 1 lit asrt_eq
	}}
	postwait {{
		\\ a thread blocks in wait (no deadline) until main posts; it receives the
		\\ posted bits that are in its mask, the rest stay pending
		: wres variable ;
		-1 lit wres !
		thread{{ 30000 lit 0 lit wait wres ! }}thread 1 lit spawn
		A lit msleep
		dup tcb 84 lit + @ 3 lit asrt_eq
		ktab nwait 1 lit asrt_eq
		ktab ntickets A lit asrt_eq                \\ a waiter holds no tickets
		dup tcb 90 lit + @ 30000 lit asrt_eq
		50000 lit over post
		join
		wres @ 10000 lit asrt_eq
	}}
	pending {{
		\\ an event posted before the wait is returned at once; taking it clears
		\\ it; unsubscribed bits stay pending for a later wait
		60000 lit getpid post
		_now 20000 lit 0 lit wait 20000 lit asrt_eq _now swap - 2710 lit u< assert
		20000 lit 1 lit wait 0 lit asrt_eq         \\ gone
		0 lit tcb 9C lit + @ 40000 lit asrt_eq
		40000 lit 1 lit wait 40000 lit asrt_eq
		0 lit tcb 9C lit + @ 0 lit asrt_eq
	}}
	uartirq {{
		\\ the UART's transmit-empty interrupt (PLIC source 10) as a doorbell:
		\\ enable it, wait on bit 10, and see the trap disable the source
		2 lit 10000001 lit c!                      \\ IER: THR empty
		A lit irqon
		_now 400 lit 186A0 lit wait 400 lit asrt_eq _now swap - 2710 lit u< assert
		K 2C lit + @ 0 lit asrt_eq                 \\ claimed from the unclaimed set
		A lit plicen swap @ and 0 lit asrt_eq      \\ disabled by the trap
		400 lit 186A0 lit wait 0 lit asrt_eq       \\ still asserted at the device, masked
		\\ the driver protocol: ack the device (drop its line), then re-enable the
		\\ source; the next event is a fresh edge and interrupts again
		0 lit 10000001 lit c!  2 lit 10000001 lit c!
		A lit irqon
		400 lit 186A0 lit wait 400 lit asrt_eq
		0 lit 10000001 lit c!
	}}
	irqrec {{
		\\ an interrupt that lands while its subscriber is running is recorded, so
		\\ the next wait returns without blocking (no lost wake-up)
		400 lit 1 lit wait drop                    \\ subscribe (times out)
		2 lit 10000001 lit c!  A lit irqon
		_now begin dup _now swap - 2710 lit u< 0= until drop   \\ 1 ms, no syscalls
		0 lit 10000001 lit c!
		0 lit tcb 9C lit + @ 400 lit asrt_eq
		_now 400 lit 0 lit wait 400 lit asrt_eq _now swap - 2710 lit u< assert
	}}
	fairness {{
		: cnt2 variable ;
		0 lit flag !  0 lit cnt !  0 lit cnt2 !
		thread{{ begin cnt @ 1 lit + cnt ! flag @ until }}thread 1 lit spawn
		thread{{ begin cnt2 @ 1 lit + cnt2 ! flag @ until }}thread 7 lit spawn
		1F4 lit msleep                             \\ 500 ms: 50 quanta, 7:1 odds
		1 lit flag !  join join
		cnt2 @ cnt @ u> assert
	}}
}}

\\ ──────────────────────────────────────────────────────────────────────────────
\\ Benches (./tools/fam --bench src/fence.fam src/proc.fam ...).  kinit happens
\\ in the first body: benches chain in file order, so every later module's bench
\\ can use the syscalls.  Each figure is one trap round trip of some kind.
\\ ──────────────────────────────────────────────────────────────────────────────

Bench {{
	\\ yield with nothing else runnable: trap in, lottery, resume the same thread
	yield1 {{
		20 lit 4 lit 1 lit kinit
		bgo
		2710 lit 0 lit do yield loop
		2710 lit bops
	}}
	\\ yield ping-pong between two threads: every yield is a context switch
	yield2 {{
		: byf variable ;
		0 lit byf !
		thread{{ begin yield byf @ until }}thread A lit spawn
		bgo
		2710 lit 0 lit do yield loop
		bstop
		1 lit byf ! join
		2710 lit bops
	}}
	\\ spawn an empty thread, run it to its exit, reap it with join
	spawn1k {{
		3E8 lit 0 lit do thread{{ }}thread 1 lit spawn join loop
		3E8 lit bops
	}}
	\\ a software event round trip: post to a waiting thread, which posts back —
	\\ two wake-ups and two context switches per op
	postwait {{
		thread{{ 3E8 lit 0 lit do 10000 lit 0 lit wait drop 20000 lit 0 lit post loop }}thread A lit spawn
		bgo
		3E8 lit 0 lit do 10000 lit over post 20000 lit 0 lit wait drop loop
		bstop join
		3E8 lit bops
	}}
	\\ the shortest sleep: trap, nothing runnable, wfi on the timer, wake, resume
	sleep1 {{
		64 lit 0 lit do 1 lit sleep loop
		64 lit bops
	}}
	\\ an interrupt doorbell: raise the UART's THRE line (a fresh edge each time),
	\\ enable the source, wait for its bit — the full trap + PLIC + wake path
	uartirq {{
		3E8 lit 0 lit do
			0 lit 10000001 lit c!  2 lit 10000001 lit c!
			A lit irqon
			400 lit 989680 lit wait 400 lit asrt_eq
		loop
		0 lit 10000001 lit c!
		3E8 lit bops
	}}
}}
"""
dst = os.path.join(ROOT, "src", "proc.fam")
open(dst, "w").write(out)
print("wrote", os.path.relpath(dst))
