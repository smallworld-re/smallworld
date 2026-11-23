    .syntax unified
    .thumb
    .text
    @ ARMv8 acquire/release: store-release the argument, load-acquire it
    @ back, then increment it with an exclusive load-acquire/store-release
    @ pair. Returns the final load-acquire in bits 7:0, the first in 15:8,
    @ and the stlex status in 23:16 (0 on success). The status register
    @ starts at 0x7f, so a status stlex never writes shows.
    @ arg 5 -> 0x000506; arg 100 -> 0x006465.
acqrel:
    sub     sp, sp, #8
    mov     r1, sp
    stl     r0, [r1]
    lda     r2, [r1]
    ldaex   r3, [r1]
    add     r3, r3, #1
    mov     r12, #0x7f
    stlex   r12, r3, [r1]
    lda     r0, [r1]
    orr     r0, r0, r2, lsl #8
    orr     r0, r0, r12, lsl #16
    add     sp, sp, #8
