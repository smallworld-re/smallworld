    .syntax unified
    .arm
    .text
    @ ARMv5TE saturating arithmetic: returns
    @ qadd(arg, 0x7FFFFFF0) ^ qdadd(arg, arg) ^ qdsub(0, arg) ^ (Q flag << 4),
    @ where Q is the sticky flag any saturation sets.
qarith:
    mvn     r1, #0x8000000F     @ 0x7FFFFFF0
    qadd    r2, r0, r1
    qdadd   r3, r0, r0
    mov     r12, #0
    qdsub   r12, r12, r0
    eor     r2, r2, r3
    eor     r2, r2, r12
    mrs     r3, cpsr
    lsr     r3, r3, #27
    and     r3, r3, #1
    eor     r0, r2, r3, lsl #4
