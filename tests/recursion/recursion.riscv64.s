    .text
_start:
    j       main
mc91:
    # Set up the stack frame
    addi    sp,sp,-8
    sd      ra,0(sp)
    
    # Check if we want case 1 or case 2
    li      a5,100
    ble     a0,a5,.L2

    # Case 1: n > 100 -> M(n) := n - 10
    addiw   a0,a0,-10
    j       .L3
.L2:
    # Case 2: n <= 100 -> M(n) := M(M(n + 11))
    addiw   a0,a0,11
    jal     ra, mc91
    jal     ra, mc91
.L3:
    # Clean up the stack frame and return
    ld      ra,0(sp)
    addi    sp,sp,8
    jr      ra
main:
    jal     ra, mc91
