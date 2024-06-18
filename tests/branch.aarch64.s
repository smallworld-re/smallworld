    .text
test:
    # This returns 1 if arg1 is 100, 0 otherwise
    cmp     x0, 100
    bne     .L2
    mov     x0, 1
    b       .L3
.L2:
    mov     x0, 0
.L3:
    nop
