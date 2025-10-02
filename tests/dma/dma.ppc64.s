    .text
divide:
    lis     5,0x5001
    addi    5,5,0x4000
    std     3,0(5)
    std     4,8(5)
    ld      3,16(5) 
    
    nop
