    .text
_start:
    e_bl    foo
bar:
    se_li   0,8
    se_mullw 0,3
    # e_cmpi can only target cr0-cr3.
    e_cmpi  1,3,101
    e_blt   1,.L2
    se_li   0,32
.L2:
    se_mr   3,0
    se_blr
foo:
    e_addi  3,3,-1
    e_bl    bar
    se_addi 3,1
