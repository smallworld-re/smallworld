    .syntax unified
    .thumb
    .text
@ Taint-propagation exercise for the Triton backend; see taint.amd64.s for the
@ data-flow the harness checks. r0/r1 are the inputs, r5 holds the scratch base.
taint:
    @ 0x3000; v6-M can only move an 8-bit immediate.
    movs    r5, #3
    lsls    r5, r5, #12
    adds    r2, r0, #1
    str     r2, [r5]
    ldr     r3, [r5]
    str     r1, [r5, #4]
    ldr     r4, [r5, #4]
    ldr     r6, [r5, #8]
    movs    r0, #0
