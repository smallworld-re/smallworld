    .text
test:
    # This returns 1 if arg1 is 100, 0 oftherwise
    cmpwi   0,3,100
    bne     0,.L2
    li      3,1
    b       .L3 
.L2:
    li      3,0
.L3: 
    nop
