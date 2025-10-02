    .text
divide:
    # DMA example modelling a hardware divisor unit
    # - Write 64-bit numerator to 0x50014000
    # - Write 64-bit denominator to 0x50014008
    # - Read 64-bit quotient from 0x50014010
    mov     x2, 0x4000
    movk    x2, 0x5001, lsl 16
    str     x0, [x2], 8
    str     x1, [x2], 8
    ldr     x0, [x2]

    nop
