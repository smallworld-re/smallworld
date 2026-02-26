    .text
test:
    cmpi.l  #100,%d0
    bne     .L2
    moveq.l #1,%d0
    bra     .L3
.L2:
    moveq.l #0,%d0
.L3:
    nop
    
