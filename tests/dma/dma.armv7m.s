    .syntax unified
    .thumb
    .text
divide:
    # DMA example modelling a hardware divisor unit
    # - Write 32-bit numerator to 0x50004000
    # - Write 32-bit denominator to 0x50004004
    # - Read 32-bit quotient from 0x50004008
    movw    r2, #0x4000
    movt    r2, #0x5000
    stm     r2!, {r0}
    stm     r2!, {r1}
    ldr     r0, [r2]
