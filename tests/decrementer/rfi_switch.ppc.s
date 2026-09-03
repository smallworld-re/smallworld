# `rfi` used as a mode switch, with no preceding exception.
#
# Firmware uses `mtspr SRR0/SRR1; rfi` to jump and set MSR atomically. The
# MPC866M controller's shadow SRR stack is empty in that case, and the SIU's
# `rfi` branch deliberately falls through and lets the instruction execute
# natively, so the backend's own SRR0 (written by the `mtspr` above, which the
# SIU also passes through) is honoured. This pins that behaviour: making the
# empty-stack case an error instead would look like hardening but would break a
# legitimate and common idiom.
    .section .text
    .globl _start
_start:
    li      3, 0
    lis     5, 0
    ori     5, 5, 0x1020      # SRR0 = _target, absolute; blob loads at 0x1000
    mtspr   26, 5             # SRR0
    li      6, 0
    mtspr   27, 6             # SRR1 = 0
    rfi                       # -> _target, not the next instruction
    li      3, 0xbad          # reached only if `rfi` was a no-op
_target:
    li      3, 0x99
    nop                       # exit point
