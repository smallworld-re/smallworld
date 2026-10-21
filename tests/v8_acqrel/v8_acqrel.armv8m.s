    .syntax unified
    .thumb
    .text
    @ ARMv8 acquire/release: store-release the argument, load-acquire it
    @ back, then increment it with an exclusive load-acquire/store-release
    @ pair. Returns (arg + 1) + arg + the stlex status (0 on success).
acqrel:
    sub     sp, sp, #8
    mov     r1, sp
    stl     r0, [r1]
    lda     r2, [r1]
    ldaex   r3, [r1]
    add     r3, r3, #1
    stlex   r12, r3, [r1]
    lda     r0, [r1]
    add     r0, r0, r2
    add     r0, r0, r12
    add     sp, sp, #8
