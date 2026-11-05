    .syntax unified
    .thumb
    .text
divide:
    # DMA example modelling a hardware divisor unit
    # - Write 32-bit numerator to 0x60004000
    # - Write 32-bit denominator to 0x60004004
    # - Read 32-bit quotient from 0x60004008
    movw    r2, #0x4000
    movt    r2, #0x6000
    stm     r2!, {r0}
    stm     r2!, {r1}
    ldr     r0, [r2]
