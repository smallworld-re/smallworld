    .text
strlen:
    li      t0,0
.L2:
    li      t1,0
    lb      t2,0(a0)
    beq     t1,t2,.L3
    addiw   t0,t0,1
    addi    a0,a0,1
    j       .L2
.L3:
    mv      a0,t0
