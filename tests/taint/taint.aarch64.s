    .text
// Taint-propagation exercise for the Triton backend; see taint.amd64.s for the
// data-flow the harness checks. x0/x1 are the inputs, x5 holds the scratch base.
taint:
    mov     x5, 0x3000
    add     x2, x0, 1
    str     x2, [x5]
    ldr     x3, [x5]
    str     x1, [x5, 8]
    ldr     x4, [x5, 8]
    ldr     x6, [x5, 16]
    mov     x0, 0
