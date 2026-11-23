    .syntax unified
    .arm
    .text
    @ ARMv5TE signed halfword multiplies, with r1 = arg rotated by 16 bits:
    @ returns (smulbb + smlabt) ^ smultt ^ smulwb ^ smlawt, then adds the
    @ smlalbb 64-bit accumulation's two words.
mul:
    ror     r1, r0, #16
    smulbb  r2, r0, r1
    smlabt  r2, r0, r1, r2
    smultt  r3, r0, r1
    smulwb  r12, r0, r1
    eor     r2, r2, r3
    eor     r2, r2, r12
    smlawt  r12, r0, r1, r0
    eor     r2, r2, r12
    mov     r3, #0
    smlalbb r2, r3, r0, r1
    add     r0, r2, r3
