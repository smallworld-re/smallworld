    .syntax unified
    .thumb
    .text
divide:
    # DMA example modelling a hardware divisor unit
    # - Write 32-bit numerator to 0x50004000
    # - Write 32-bit denominator to 0x50004004
    # - Read 32-bit quotient from 0x50004008
    # v6-M can only move an 8-bit immediate, so build the address.
    movs    r3, #0x50
    lsls    r3, r3, #24
    movs    r2, #0x40
    lsls    r2, r2, #8
    orrs    r2, r2, r3
    stm     r2!, {r0}
    stm     r2!, {r1}
    ldr     r0, [r2]
