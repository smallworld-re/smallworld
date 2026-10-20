    .syntax unified
    .thumb
    .text
_start:
    bl      main
strlen:
    movs    r1, #0
.L0:
    ldrb    r2, [r0]
    cmp     r2, #0
    beq     .L1
    adds    r1, r1, #1
    adds    r0, r0, #1
    b       .L0
.L1:
    mov     r0, r1
    bx      lr
main:
    bl      strlen
