# MPC860 decrementer/timebase shadow read-back.
#
# The other decrementer fixtures arm DEC with 100, which is under one executor
# stride (1000 instructions), so the very first tick underflows and the countdown
# arithmetic in MtsprStateManager::tick is never distinguished from a constant
# `true`. This one arms DEC with 0x10000 - about 65 strides - spins for a dozen
# strides, and then reads DEC and the timebase back, which is also the only
# coverage of the `mfspr DEC` / `mftb` shadow branch in `mtspr_proxy`.
#
# DEC is armed before the first stride boundary and TB starts at 0, so both
# shadows move by the same amount and `DEC + TBL == 0x10000` exactly. tests/
# unit.py asserts that rather than a fuzzy range.
#
# Loaded at 0x1000 with PC at the first instruction (no `_vector` prologue);
# the trailing nop is the exit point.
    .section .text
    .globl _start
_start:
    lis     5, 0x0001
    ori     5, 5, 0x0000      # DEC = 0x10000: far more than one stride
    mtspr   22, 5
    li      7, 4000
_spin:
    addic.  7, 7, -1
    bne     _spin             # ~8000 instructions, ~8 strides
    mfspr   3, 22             # r3 = DEC shadow, counted down from 0x10000
    mftb    4                 # r4 = TBL shadow, counted up from 0
    nop                       # exit point
