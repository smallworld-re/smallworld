    .text
divide:
    # DMA example modelling a hardware divisor unit
    # - Write 32-bit numerator to 0x50014000
    # - Write 32-bit denominator to 0x50014004
    # - Read 32-bit quotient from 0x50014008
    lui     t0, 0x50014
    sw      a0, 0x0(t0)
    sw      a1, 0x4(t0)
    lw      a0, 0x8(t0)
