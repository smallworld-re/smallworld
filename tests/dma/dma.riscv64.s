    .text
divide:
    # DMA example modelling a hardware divisor unit
    # - Write 64-bit numerator to 0x50014000
    # - Write 64-bit denominator to 0x50014008
    # - Read 64-bit quotient from 0x50014010
    lui     t0, 0x50014
    sd      a0, 0x0(t0)
    sd      a1, 0x8(t0)
    ld      a0, 0x10(t0)
    nop
