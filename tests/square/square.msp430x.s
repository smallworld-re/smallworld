    .text
_start:
    # Multiply r15 by r15 using shift-and-add so the pcode-backed engines
    # don't spend thousands of iterations in the naive repeated-add loop.
    mov     #0, r14
    mov     r15, r12
    mov     r15, r13

.L2:
    tst     r12
    jz      .L3

    clrc
    rrc     r12
    jnc     .L4
    add     r13, r14

.L4:
    rla     r13
    jmp     .L2

.L3:
    nop
