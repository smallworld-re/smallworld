# `rfi` used as a mode switch, with no preceding exception.
#
# Firmware uses `mtspr SRR0/SRR1; rfi` to jump and set MSR atomically. This pins
# that the SIU's `rfi` branch honours the SRR0/SRR1 the guest just wrote rather
# than swallowing the instruction or diverting it somewhere else: making this an
# error, or preferring some other saved state, would look like hardening but
# would break a legitimate and common idiom.
#
# `li 3, 0xbad` must branch past `_target`; without that branch it falls straight
# into `li 3, 0x99` and the test passes whether or not `rfi` transferred control.
    .section .text
    .globl _start
_start:
    li      3, 0
    lis     5, 0
    ori     5, 5, 0x1024      # SRR0 = _target, absolute; blob loads at 0x1000
    mtspr   26, 5             # SRR0
    li      6, 0
    mtspr   27, 6             # SRR1 = 0
    rfi                       # -> _target, not the next instruction
    li      3, 0xbad          # reached only if `rfi` was a no-op
    b       _done             # ... and this keeps 0xbad from being overwritten
_target:
    li      3, 0x99
_done:
    nop                       # exit point
