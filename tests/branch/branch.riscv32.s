    .text
test:
    # Return 1 if arg1 is 100, 0 otherwise
    li  a5,100
    bne a0,a5,.L2
    li  a0,1
    j   .L3
.L2:
    li  a0,0
.L3:
    nop    
