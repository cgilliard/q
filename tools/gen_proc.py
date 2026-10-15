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
""")

RESTORE = asm("""
    csrr    t0, mscratch            # K
    lw      t1, 0(t0)               # TCB to resume
    lw      t2, 128(t1)
    csrw    mepc, t2
    li      t2, 0x1880              # MPP = M, MPIE = 1 (interrupts on after mret)
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
# runtime push of its FINAL address.  The compiler assembles the program in its
# own heap, with s0 = output start; the image is loaded at 0x80000000, so the
# final address is 0x80000000 + (cursor - s0).  (stdlib's `lit` pushes the raw
# value, which is why `here lit` cannot be used for runtime addresses.)
ADDR_EMIT = asm("""
    lw      t0, 0(tp)
    addi    tp, tp, 4
    sub     t0, t0, s0
    lui     t1, 0x80000
    add     t0, t0, t1              # final address
    li      t6, 0x800
    add     t1, t0, t6
    srli    t1, t1, 12              # %hi (rounded so a set bit 11 in %lo is right)
    slli    t2, t1, 12
    sub     t2, t0, t2              # %lo, signed
    li      t3, 0xFFF
    and     t2, t2, t3
    slli    t4, t1, 12
    ori     t4, t4, 0x337           # lui t1, %hi
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
\\ 0 is the program's original context; threads 1..15 get a 128 KiB slot each
\\ (RID stack, heap + data stack, loop stack) carved from the main heap by
\\ `kinit`.
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
\\   kinit                     set up the table, timer and trap vector (once)
\\   thread{{ ... }}thread       compile a thread body; at runtime pushes its address
\\   spawn   ( addr tickets -- tid )   new thread, 0 if the table is full
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
\\
\\ Sleeping and waiting threads hold no tickets.  When nothing is runnable the
\\ scheduler arms the timer for the earliest deadline and waits in `wfi`, which
\\ returns on the timer or a PLIC interrupt; when nothing is runnable, sleeping
\\ or waiting the program is finished.
\\
\\ Layout — TCB (0xA0 bytes, 16 of them):  4*n saved x_n   80 pc   84 state
\\   (0 free, 1 runnable, 2 sleeping, 3 waiting)   88 tickets   8C pid
\\   90 wait mask   94 wake lo   98 wake hi   9C pending events.
\\ Kernel block K:  0 current   4 t1 stash   8 table   C rng   10 slot pool
\\   14 ksp   18 ks8   1C ks11   20 kgp   24 quantum   28 ticks   2C IRQ events
\\   that no thread was subscribed to (claimed by the next wait that asks).
\\ Slot (0x20000 bytes): [0,1000) RID stack (s11 down)   [1000,1C000) heap (gp
\\   up) + data stack (sp down)   [1C000,20000) loop stack (s8 down).  Slot 0
\\   holds the kernel's own stacks.  s10 stays global so `variable` cells are
\\   shared by every thread.
\\ ──────────────────────────────────────────────────────────────────────────────

\\ ── compile-time helpers ──────────────────────────────────────────────────────

\\ ,addr  ( C: cursor -- )  emit a runtime push of the FINAL address of an output
\\ cursor taken with `here`.  The compiler assembles in its own heap (s0 = output
\\ start) and the image loads at 0x80000000, so this pushes 0x80000000 + (cursor -
\\ s0).  (`lit` would push the raw cursor.)
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
            rand swap %
            ktab swap pickt {DBG2}K !
            -1 lit
        then
    until ;

\\ ── syscalls ──────────────────────────────────────────────────────────────────
\\ 0 yield   1 exit   2 spawn ( addr tickets -- tid )   3 getpid ( -- tid )
\\ 4 sleep ( ticks -- )   5 wait ( mask ticks -- events )   6 post ( mask tid -- )

: slotof ( i -- base )  20000 lit * K 10 lit + @ + ;

\\ build a fresh context in tcb for the body at addr
: tinit ( tickets addr tcb -- )
    dup zregs                           \\ tickets addr tcb
    dup 8C lit + @ slotof               \\ tickets addr tcb slot
    2dup 1000 lit + swap 6C lit + !     \\ s11 = slot + 0x1000 (RID top)
    2dup 1000 lit + swap C lit + !      \\ gp  = slot + 0x1000 (heap base)
    2dup 1C000 lit + swap 8 lit + !     \\ sp  = slot + 0x1C000 (data stack top)
    20000 lit + over 60 lit + !         \\ s8  = slot + 0x20000 (loop stack top)
    cur 68 lit + @ over 68 lit + !      \\ s10 = the global RID floor / var base
    dup 1 lit swap 84 lit + !           \\ state = runnable
    dup 0 lit swap 90 lit + !           \\ no subscription
    dup 0 lit swap 9C lit + !           \\ no pending events
    swap over 80 lit + !                \\ pc = addr          ( tickets tcb )
    88 lit + ! ;                        \\ tickets

: spid variable ;
: sysspawn ( -- )
    upop upop                           \\ tickets addr
    ktab findfree dup 0= if
        drop 2drop 0 lit upush
    else
        dup 8C lit + @ spid !
        tinit spid @ upush
    then ;

: sysexit ( -- )  0 lit cur 84 lit + ! ;
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
    drop then then then then then then then ;

: khalt  begin wfi 0 lit until ;

\\ the trap entry: everything between the two asm pieces is ordinary fam running
\\ on the kernel's stacks with interrupts masked.
: ktrap ( -- )
    mcause@ {DBG0}
    dup 80000007 lit = if drop K 28 lit + dup @ 1 lit + swap ! else
    dup 8000000B lit = if drop irq! else
    dup B lit = if drop syscall! else
        "proc: unexpected trap " puts u.x '\\n' lit putc khalt
    then then then
    sched arm ;


\\ ── user words ────────────────────────────────────────────────────────────────

: yield   ( -- )               0 lit syscall ;
: texit   ( -- )               1 lit syscall ;
: spawn   ( addr tickets -- tid ) 2 lit syscall ;
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

\\ ── kinit ─────────────────────────────────────────────────────────────────────

: kinit ( -- )
    \\ K block, the table, the slot pool
    40 lit alloc kblk !
    0 lit K 28 lit + !                  \\ ticks = 0
    0 lit K 2C lit + !                  \\ no unclaimed interrupts
    A00 lit alloc K 8 lit + !           \\ 16 TCBs, zeroed, pid = index
    10 lit 0 lit do
        i tcb dup
        A0 lit 0 lit do 0 lit over i + ! loop
        i swap 8C lit + ! drop
    loop
    200000 lit alloc K 10 lit + !       \\ 16 slots of 128 KiB
    \\ the kernel's own stacks live in slot 0
    0 lit slotof
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
		kinit
		getpid 0 lit asrt_eq
		cur 0 lit tcb asrt_eq
		0 lit tcb 84 lit + @ 1 lit asrt_eq         \\ thread 0 runnable
		0 lit tcb 88 lit + @ A lit asrt_eq         \\ 10 tickets
		K 24 lit + @ 186A0 lit asrt_eq             \\ 10 ms quantum
		ktab ntickets A lit asrt_eq
		ktab nwait 0 lit asrt_eq
		ktab findfree 1 lit tcb asrt_eq            \\ slot 1 is the first free
		K 1C lit + @ 0 lit slotof 1000 lit + asrt_eq
		K 14 lit + @ 0 lit slotof 1C000 lit + asrt_eq
	}}
	table {{
		3 lit tcb 0 lit tcb - 1E0 lit asrt_eq
		10 lit 0 lit do
			i tcb 8C lit + @ i asrt_eq             \\ pid = index
			i tcb 84 lit + @ i 0= 1 lit and asrt_eq          \\ only 0 is live
		loop
		1 lit slotof 0 lit slotof - 20000 lit asrt_eq
	}}
	rand {{
		K C lit + @                                \\ save the seed
		1 lit K C lit + !
		rand 42021 lit asrt_eq
		rand 4080601 lit asrt_eq
		rand 9DCCA8C5 lit asrt_eq
		K C lit + !
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
		thread{{ }}thread 3 lit swap F lit tcb tinit
		F lit tcb 84 lit + @ 1 lit asrt_eq
		F lit tcb 88 lit + @ 3 lit asrt_eq
		F lit tcb 8C lit + @ F lit asrt_eq
		F lit tcb 8 lit + @ F lit slotof 1C000 lit + asrt_eq    \\ sp
		F lit tcb C lit + @ F lit slotof 1000 lit + asrt_eq     \\ gp
		F lit tcb 6C lit + @ F lit slotof 1000 lit + asrt_eq    \\ s11
		F lit tcb 60 lit + @ F lit slotof 20000 lit + asrt_eq   \\ s8
		F lit tcb 68 lit + @ 0 lit tcb 68 lit + @ asrt_eq       \\ s10 shared
		F lit tcb 4 lit + @ 0 lit asrt_eq                       \\ ra zeroed
		0 lit F lit tcb 84 lit + !
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
	}}
	stacks {{
		: tgp variable ;
		: mgp variable ;
		0 lit alloc mgp !
		thread{{ sp@ tsp !  10 lit alloc tgp ! }}thread 1 lit spawn join
		tsp @ 1 lit slotof 1000 lit + u> assert
		tsp @ 1 lit slotof 1C000 lit + 4 lit + u< assert
		tgp @ 1 lit slotof 1000 lit + asrt_eq
		0 lit alloc mgp @ asrt_eq                  \\ thread allocs do not move ours
	}}
	yield {{
		yield
		0 lit sleep
		getpid 0 lit asrt_eq
	}}
	tabfull {{
		: flag variable ;
		0 lit flag !
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
		0 lit wlogn !  0 lit wlog !
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
"""
dst = os.path.join(ROOT, "src", "proc.fam")
open(dst, "w").write(out)
print("wrote", os.path.relpath(dst))
