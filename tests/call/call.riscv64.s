    .text
_start:
    jal     x0, foo

bar:
    add     t0, a0, zero
    li      t1, 8
    mul     a0, a0, t1
    
    li      t1, 101
    blt     t0, t1, .L2
    li      a0, 32
    
.L2:
    ret
    
foo:
    addi    a0, a0, -1
    jal     x1, bar
    addi    a0, a0, 1
 
