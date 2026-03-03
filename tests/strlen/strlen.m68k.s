    .text
_start:
    mova.l  4(%sp), %a0
    clr.l   %d0 
.L2:
    move.b  (%a0)+, %d1
    cmpi.b  #0, %d1
    beq     .L3

    addi.l  #1, %d0
    bra     .L2
.L3:
    nop
