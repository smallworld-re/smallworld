    .text
test:
    # This returns 1 if arg1 is 100, 0 otherwise
    e_cmpi  0,3,100
    e_bne   0,.L2
    se_li   3,1
    se_b    .L3
.L2:
    se_li   3,0
.L3:
    se_nop
