    ; Arithmetic: add, addc, subb in every addressing mode, inc, dec, mul,
    ; div and da, on random operands and a random carry.
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
    mov     r0, #0x34
    add     a, r2
    SNAP    0x40
    addc    a, 0x22
    SNAP    0x42
    addc    a, @r0
    SNAP    0x44
    addc    a, #0x7F
    SNAP    0x46
    subb    a, r3
    SNAP    0x48
    subb    a, 0x23
    SNAP    0x4A
    subb    a, @r0
    SNAP    0x4C
    subb    a, #0x80
    SNAP    0x4E
    add     a, #0xFF
    SNAP    0x50
    addc    a, #0xFF
    SNAP    0x52
    subb    a, #0xFF
    SNAP    0x54
    inc     a
    inc     r4
    inc     0x24
    inc     @r0
    inc     dptr
    dec     a
    dec     r5
    dec     0x25
    dec     @r0
    SNAP    0x56
    mov     b, r6
    mul     ab
    SNAP    0x58
    mov     0x5A, b
    mov     a, r7
    mov     b, r6
    orl     b, #0x01        ; never divide by zero
    div     ab
    SNAP    0x5C
    mov     0x5E, b
    mov     a, 0x26
    add     a, 0x27
    da      a
    SNAP    0x60
    mov     a, 0x28
    addc    a, 0x29
    da      a
    SNAP    0x62
    nop
