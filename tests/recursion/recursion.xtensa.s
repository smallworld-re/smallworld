    .text
_start:
    call0   main

# Whoever made an ISA with 24-bit instructions
# require 32-bit call target alignment is not my friend...
.byte 0x00

mc91:
    # Set up the stack frame
    addi    $sp, $sp, -4
    s32i    $a0, $sp, 0

    # Check if we want case 1 or case 2
    movi    $a3, 101
    blt     $a2, $a3, .L2

    # Case 1: n > 100 -> M(n) := n - 10
    movi    $a3, -10
    add     $a2, $a2, $a3
    j       .L3
    .byte 0x00

.L2:
    # Case 2: n <= 100 -> M(n) := M(M(n + 11))
    addi    $a2, $a2, 11
    call0   mc91
    call0   mc91

.L3:
    # Clean up the stack and return    
    l32i    $a0, $sp, 0
    addi    $sp, $sp, 4
    ret

main:
    call0   mc91
