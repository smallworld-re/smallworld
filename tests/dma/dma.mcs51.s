    ; Divide r7 by r5 with the memory-mapped divider the harness models.  The
    ; divider sits in XDATA at 0x5000 with four 16-bit big-endian registers:
    ; numerator, denominator, quotient, remainder.  movx moves one byte at a
    ; time; writing the denominator's low byte starts the division.  The
    ; quotient comes back in DPTR.
    .area CSEG (CODE)
divide:
    mov     dptr, #0x5000
    clr     a
    movx    @dptr, a        ; numerator, high byte
    inc     dptr
    mov     a, r7
    movx    @dptr, a        ; numerator, low byte
    inc     dptr
    clr     a
    movx    @dptr, a        ; denominator, high byte
    inc     dptr
    mov     a, r5
    movx    @dptr, a        ; denominator, low byte
    inc     dptr
    movx    a, @dptr        ; quotient, high byte
    mov     r6, a
    inc     dptr
    movx    a, @dptr        ; quotient, low byte
    mov     dpl, a
    mov     dph, r6
    nop
