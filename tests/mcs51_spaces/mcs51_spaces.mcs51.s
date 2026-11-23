    ; One access to each 8051 address space, through each way of reaching it.
    ; harness/scenarios/mcs51.py checks where every value landed.
    .area CSEG (CODE)
_start:
    mov     0x30, #0x5A     ; internal RAM, direct
    mov     r0, #0x40
    mov     @r0, #0x11      ; internal RAM, indirect
    mov     dptr, #0x1234
    mov     a, #0x22
    movx    @dptr, a        ; external RAM
    mov     0x31, 0x30      ; internal RAM to internal RAM
    mov     a, 0x31
    mov     r1, a
    mov     0x90, #0x77     ; SFR (P1)
    mov     0x80, 0x90      ; SFR to SFR (P0 = P1)
    mov     dptr, #table
    clr     a
    movc    a, @a+dptr      ; code
    mov     r2, a
    mov     a, #0x15
    add     a, #0x27        ; BCD 15 + 27: binary 0x3C
    da      a               ; 0x42
    mov     r3, a
    mov     dptr, #0x1234
    movx    a, @dptr        ; external RAM read
    mov     r4, a
    mov     a, @r0          ; internal RAM indirect read
    mov     r5, a
    push    acc             ; stack in internal RAM, above SP
    pop     b
    nop
table:
    .db     0xC3
