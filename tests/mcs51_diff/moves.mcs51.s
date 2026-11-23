    ; Data movement: mov in every form, upper internal RAM through @Ri, movx,
    ; movc, xch, xchd, push and pop, of SP too.
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
    sjmp    .Lmain
.Ltable:
    .db     0xA5, 0xC3, 0x96, 0x3C
.Lmain:
    mov     r0, #0xC4       ; upper internal RAM: indirect only
    mov     a, @r0
    SNAP    0x40
    mov     @r0, 0x22
    mov     r1, #0x38
    mov     0x39, @r1
    mov     @r1, #0x6C
    mov     0x3A, 0x23
    mov     0x3B, #0x4D
    mov     r2, 0x24
    mov     0x3C, r3
    mov     dptr, #0x0040
    movx    a, @dptr
    SNAP    0x42
    inc     dptr
    movx    @dptr, a
    mov     0xA0, #0x00     ; P2 = 0: movx @Ri's high address byte
    mov     r1, #0x50
    movx    a, @r1
    SNAP    0x44
    mov     r1, #0x51
    movx    @r1, a
    mov     dptr, #.Ltable
    mov     a, #2
    movc    a, @a+dptr
    SNAP    0x46
    mov     a, #1
    movc    a, @a+pc
    sjmp    .Lpast
    .db     0x11, 0x22
.Lpast:
    SNAP    0x48
    xch     a, r4
    SNAP    0x4A
    xch     a, 0x25
    SNAP    0x4C
    mov     r0, #0x3D
    xch     a, @r0
    SNAP    0x4E
    xchd    a, @r0
    SNAP    0x50
    push    0x26
    push    0x27
    pop     0x3E
    pop     0x3F
    mov     a, sp
    SNAP    0x52
    push    sp              ; pushes SP as it was
    mov     a, sp
    SNAP    0x54
    pop     sp              ; leaves SP the byte popped
    mov     a, sp
    SNAP    0x56
    nop
