    .text
@ Taint-propagation exercise for the Triton backend; see taint.amd64.s for the
@ data-flow the harness checks. r0/r1 are the inputs, r5 holds the scratch base.
taint:
    mov     r5, #0x3000
    add     r2, r0, #1
    str     r2, [r5]
    ldr     r3, [r5]
    str     r1, [r5, #4]
    ldr     r4, [r5, #4]
    ldr     r6, [r5, #8]
    mov     r0, #0
