    .text
strlen:
    li      4,0
    extsw   4,4
.L2:
    lbz     5,0(3)
    cmpwi   5,5,0
    beq     5,.L3
    addi    3,3,1
    addi    4,4,1
    extsw   4,4
    b       .L3
.L3:
    mr      3,4
    blr
    
