    .text
vuln:
    mova.l  4(%sp), %a0
    cmpi.l  #11, 0(%a0)
    bls     .L5
    cmpi.b  #98, 4(%a0)
    beq     .L7

.L3:
    clr.l   %d0
    bra     .FAKERET

.L7:
    cmpi.b  #97, 5(%a0)
    bne     .L3
    cmpi.b  #100, 6(%a0)
    bne     .L3
    cmpi.b  #33, 7(%a0)
    bne     .L3
    move.b  8(%a0), %d0

    # Building constants in m68k is a PAIN
    clr     %d1
    move.l  %d1, %a0
    adda.l  #0x1234, %a0
    move.l  %a0, %d1
    lsl.l   #8, %d1
    lsl.l   #8, %d1
    move.l  %d1, %a0
    adda.l  #0x5678, %a0

    move.l  %d0, 0(%a0)
    

.L5:
    movq.l  #-1, %d0

.FAKERET: 
    nop
