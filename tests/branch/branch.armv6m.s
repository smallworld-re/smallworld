    .syntax unified
    .thumb
    .text
test:
    # This returns 1 if arg1 is 100, 0 otherwise
    cmp     r0, #100
    bne     .L2
    movs    r0, #1
    b       .L3
.L2:
    movs    r0, #0
.L3:
    nop
