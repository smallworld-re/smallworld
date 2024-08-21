    .text
strlen:
    li      a5,0
.L2:
    li      a6,0
    lb      a7,0(a0)
    beq     a6,a7,.L3
    addiw   a5,a5,1
    addi    a0,a0,1
    j       .L2
.L3:
    mv      a0,a5
    jr      ra
