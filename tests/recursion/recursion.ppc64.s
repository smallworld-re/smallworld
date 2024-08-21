    .text
mc91:
    # Set up the stack frame
    mflr    0
    std     0,16(1)
    stdu    1,-112(1)
    
    # Check if we want case 1 or case 2
    cmpwi   0,3,100
    ble     0,.L2

    # Case 1: n > 100 -> M(n) := n - 10
    addi    3,3,-10
    extsw   3,3
    b       .L3
.L2:
    # Case 2: n <= 100 -> M(n) := M(M(n + 11))
    addi    3,3,11
    extsw   3,3
    bl      mc91
    bl      mc91
    extsw   3,3
.L3:
    # Clean up the stack and return
    addi    1,1,112
    ld      0,16(1)
    mtlr    0
    blr
