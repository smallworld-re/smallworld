    .text
_start:
    e_bl    main

strlen:
    se_li   4,0
.L2:
    se_lbz  5,0(3)
    # e_cmpi can only target cr0-cr3.
    e_cmpi  1,5,0
    e_beq   1,.L3
    se_addi 4,1
    se_addi 3,1
    se_b    .L2
.L3:
    se_mr   3,4
    se_blr

main:
    e_bl    strlen
