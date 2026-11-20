    .text
_start:
    e_bl    main

mc91:
    # Set up the stack frame
    e_stwu  1,-16(1)
    se_mflr 0
    e_stw   0,20(1)
    e_stw   31,12(1)
    se_mr   31,1

    # Check if we want case 1 or case 2
    e_cmpi  0,3,100
    e_ble   0,.L2

    # Case 1: n > 100 -> M(n) := n - 10
    e_addi  3,3,-10
    se_b    .L3
.L2:
    # Case 2: n <= 100 -> M(n) := M(M(n + 11))
    e_addi  3,3,11
    e_bl    mc91
    e_bl    mc91
.L3:
    # Clean up the stack and return
    e_lwz   0,20(1)
    e_lwz   31,12(1)
    se_mtlr 0
    e_addi  1,1,16
    se_blr

main:
    e_bl    mc91
