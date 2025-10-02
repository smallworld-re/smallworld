    .text
    .literal_position
    .literal .LC0, 0x50014000
    .align 4
    .global divide
divide:
    # DMA example modelling a hardware divisor unit
    # - Write 32-bit numerator to 0x50014000
    # - Write 32-bit denominator to 0x50014004
    # - Read 32-bit quotient from 0x50014008
    #
    # XTensa's immediates are pitifully small,
    # so it loads long literals from memory
    l32r    $a4, .LC0
    s32i    $a2, $a4, 0
    s32i    $a3, $a4, 4
    l32i    $a2, $a4, 8
    nop
