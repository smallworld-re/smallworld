    ; Logic: anl, orl, xrl in every form, cpl, clr, the rotates and swap.
    ; Part of the mcs51_diff scenario; see harness/scenarios/mcs51_diff.py.
    ; It starts from a random state (registers, PSW flags, internal RAM
    ; 0x20-0xFF and XDATA 0x0000-0x00FF) and the scenario compares where it
    ; ends against ucsim_51.  SNAP saves A, and PSW without the parity bit,
    ; which SmallWorld does not compute, to internal RAM.  Programs stay out
    ; of internal RAM 0x08-0x1F and leave the register bank alone; SmallWorld
    ; does not model banks.

    .macro SNAP slot
    mov     slot, a
    push    acc
    mov     a, psw
    anl     a, #0xFE
    mov     slot+1, a
    pop     acc
    .endm

    .area CSEG (CODE)
_start:
    mov     r1, #0x35
    anl     a, r2
    SNAP    0x40
    orl     a, 0x22
    SNAP    0x42
    xrl     a, @r1
    SNAP    0x44
    anl     a, #0xF7
    orl     a, #0x21
    xrl     a, #0x5A
    SNAP    0x46
    anl     0x30, a
    orl     0x31, a
    xrl     0x32, a
    anl     0x33, #0x3C
    orl     0x36, #0x81
    xrl     0x37, #0xFF
    cpl     a
    SNAP    0x48
    rl      a
    SNAP    0x4A
    rlc     a
    SNAP    0x4C
    rr      a
    SNAP    0x4E
    rrc     a
    SNAP    0x50
    swap    a
    SNAP    0x52
    cpl     c
    rlc     a
    SNAP    0x54
    clr     a
    SNAP    0x56
    nop
