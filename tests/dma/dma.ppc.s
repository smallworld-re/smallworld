    .text
divide:
    lis     5,0x5001
    addi    5,5,0x4000
    stw     3,0(5)
    stw     4,4(5)
    lwz     3,8(5) 

    
