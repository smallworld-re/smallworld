    ; Bit instructions: setb, clr, cpl, mov, anl and orl on bits of internal
    ; RAM and of ACC, B and PSW; jb, jnb and jbc.
    ; Part of the mcs51_diff scenario; see harness/scenarios/mcs51_diff.py.
    ; It starts from a random state (registers, PSW flags, internal RAM
    ; 0x20-0xFF and XDATA 0x0000-0x00FF) and the scenario compares where it
    ; ends against ucsim_51.  SNAP saves A and PSW to internal RAM.

    .macro SNAP slot
    mov     slot, a
    mov     slot+1, psw
    .endm

    .area CSEG (CODE)
_start:
    setb    0x00            ; internal RAM 0x20 bit 0
    clr     0x0F            ; internal RAM 0x21 bit 7
    cpl     0x13            ; internal RAM 0x22 bit 3
    setb    0xE1            ; ACC.1
    clr     0xE6            ; ACC.6
    cpl     0xF4            ; B.4
    setb    0xD5            ; PSW.5, F0
    SNAP    0x40
    mov     0x42, b
    mov     c, 0x1A         ; internal RAM 0x23 bit 2
    SNAP    0x44
    mov     0x2C, c         ; internal RAM 0x25 bit 4
    anl     c, 0x31         ; internal RAM 0x26 bit 1
    SNAP    0x46
    orl     c, /0x3F        ; NOT internal RAM 0x27 bit 7
    SNAP    0x48
    anl     c, /0x45        ; NOT internal RAM 0x28 bit 5
    SNAP    0x4A
    orl     c, 0xF2         ; B.2
    SNAP    0x4C
    mov     0x3F, #0
    jb      0x50, .L1       ; internal RAM 0x2A bit 0
    orl     0x3F, #0x01
.L1:
    mov     a, 0x3F
    jnb     0x58, .L2       ; internal RAM 0x2B bit 0
    orl     a, #0x02
.L2:
    jbc     0x60, .L3       ; internal RAM 0x2C bit 0
    orl     a, #0x04
.L3:
    SNAP    0x4E
    cpl     c
    SNAP    0x50
    nop
