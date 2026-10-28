    ; 8051 behaviour that Ghidra's stock 8051 language gets wrong, and that
    ; nix/patches/ghidra-8051.patch fixes.  harness/scenarios/mcs51.py checks
    ; the results.
    .area CSEG (CODE)
_start:
    mov     sp, #0x50       ; SP through its SFR address, 0x81
    setb    0x03            ; bit 3 of internal RAM 0x20
    setb    0xE7            ; ACC.7, a bit of a register-backed SFR
    mov     r7, a           ; 0x80
    clr     c
    mov     a, #0xFF
    add     a, #0x01        ; 0: CY and AC set
    mov     r6, psw
    mov     a, #0x01
    addc    a, #0xFF        ; 1 + 0xFF + carry = 0x101: CY set
    mov     r5, psw
    mov     r4, a
    setb    c
    mov     a, #0x10
    subb    a, #0xFF        ; 0x10 - 0xFF - borrow: 0x10, borrow out
    mov     r3, a
    mov     r2, psw
    setb    0xD5            ; F0, a user flag
    clr     c
    mov     a, #0x7F
    add     a, #0x01        ; 0x80: OV and AC set, F0 untouched
    mov     r1, psw
    mov     a, #0x19
    add     a, #0x28        ; BCD 19 + 28, which needs AC
    da      a               ; 0x47
    mov     r0, a
    push    acc             ; to 0x51
    nop
