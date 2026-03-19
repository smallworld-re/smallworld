    .text
divide:
    # DMA example modelling a hardware divisor unit
    # - Write 32-bit numerator to 0x50014000
    # - Write 32-bit denominator to 0x50014004
    # - Read 32-bit quotient from 0x500140008
    # - Pray the emulator is using a 32-bit address bus, not the old 24-bit one.

    # Building 32-bit values in m68k is a pain.
    movq.l      #0x50,%d2
    lsl.l       #8,%d2
    ori.l       #0x01,%d2
    lsl.l       #8,%d2
    ori.l       #0x40,%d2
    lsl.l       #8,%d2
    mova.l      %d2,%a0

    mov.l       %d0,(%a0)+
    mov.l       %d1,(%a0)+
    mov.l       (%a0)+,%d0
