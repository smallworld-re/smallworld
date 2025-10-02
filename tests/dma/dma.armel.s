    .text
divide:
    # DMA example modelling a hardware divisor unit
    # - Write 32-bit numerator to 0x50014000
    # - Write 32-bit denominator to 0x50014004
    # - Read 32-bit quotient from 0x50014008
    mov     r3, #0x5000
    mov     r2, #0x4000
    orr     r2, r2, r3, lsl #16
    stm     r2!, {r0}
    stm     r2!, {r1}
    ldr     r0, [r2]
    
    nop
