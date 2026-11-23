    .text
divide:
    ! DMA example modelling a hardware divisor unit
    ! - Write 32-bit numerator to 0x50014000
    ! - Write 32-bit denominator to 0x50014004
    ! - Read 32-bit quotient from 0x50014008
    sethi   %hi(0x50014000), %o2
    st      %o0, [%o2]
    st      %o1, [%o2 + 4]
    ld      [%o2 + 8], %o0
