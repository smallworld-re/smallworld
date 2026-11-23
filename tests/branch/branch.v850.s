    .text
test:
    mov     0, r10
    # cmp takes a 5-bit immediate, so 100 goes through a register.
    movea   100, r0, r11
    cmp     r11, r6
    bne     .Ldone
    mov     1, r10
.Ldone:
