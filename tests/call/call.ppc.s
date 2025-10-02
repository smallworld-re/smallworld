    .text
_start:
    bl      foo
bar:
    li      0,8
    mullw   0,0,3
    cmpwi   4,3,101
    blt     4,.L2
    li      0,32
.L2:  
    mr      3,0
    blr
foo:
    addi    3,3,-1
    bl      bar
    addi    3,3,1
