# MPC860 (PowerQUICC I) decrementer exception round trip.
#
# Exercises the whole MPC866M exception path end to end: the SIU tick advancing
# DEC, the underflow latching a Decrementer, the controller vectoring to 0x900
# with the entry MSR, and - the part nothing else covers - the `rfi` that
# restores PC/MSR from the controller's shadow SRRs.
#
# The blob is loaded at 0x900 so that `_vector` lands exactly on the MPC8xx
# decrementer vector; `_start` follows at 0x920 and is where the emulator sets
# PC.  Keep `.balign 32` and the 0x900 load address in step with
# tests/unit.py's StyxPowerPCExecutionTests._run_decrementer.
    .section .text
    .globl _start

# ---- decrementer vector (0x900) ----------------------------------------
_vector:
    li      3, 0x5a           # marker: the handler ran
    lis     5, 0x7fff
    ori     5, 5, 0xffff
    mtspr   22, 5             # DEC = 0x7fffffff, so it will not fire again
    rfi                       # <- restores PC/MSR from the shadow SRRs

# ---- main --------------------------------------------------------------
    .balign 32
_start:
    li      3, 0              # r3 stays 0 unless the handler runs
    li      5, 100
    mtspr   22, 5             # arm DEC: underflows on the first stride
    # Build MSR from scratch rather than OR-ing MSR[EE] into the reset value.
    # The MPC8xx comes out of reset with MSR[IP] set, which puts the exception
    # vectors at 0xFFF00000; real firmware clears IP once it has vectors in low
    # memory, and this fixture covers that low-vector path.  Its sibling
    # decrementer_ip.ppc.s keeps IP set and covers the high vectors.
    li      6, 0
    ori     6, 6, 0x8000      # MSR = EE only: IP=0, so vectors are at 0x000
    mtmsr   6                 # unmask -> the latched decrementer can deliver
    # Bound the spin.  Delivery needs a couple of 1000-instruction strides, and
    # 20000 iterations is ~60 of them; if the exception never arrives the loop
    # still terminates with r3 == 0 and the test FAILS on the assertion instead
    # of hanging the suite forever - which is the failure mode this whole change
    # set exists to remove.
    li      7, 20000
_wait:
    cmpwi   3, 0
    bne     _done             # handler ran
    addic.  7, 7, -1
    bne     _wait
_done:
    nop                       # exit point
