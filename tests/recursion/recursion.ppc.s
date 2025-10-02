    .text
_start:
    bl      main

mc91:
    # Set up the stack frame
    stwu    1,-16(1)
    mflr    0
    stw     0,20(1)
    stw     31,12(1)
    mr      31,1

    # Check if we want case 1 or case 2
    cmpwi   0,3,100
    ble     0,.L2
    
    # Case 1: n > 100 -> M(n) := n - 10
    addi    3,3,-10
    b       .L3
.L2:
    # Case 2: n <= 100 -> M(n) := M(M(n + 11))
    addi    3,3,11
    bl      mc91
    bl      mc91
.L3:
    # Clean up the stack and return
    lwz     0,20(1)
    lwz     31,12(1)
    mtlr    0
    addi    1,1,16
    blr
    
main:
    bl mc91    
    nop
