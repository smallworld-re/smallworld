    .text
mc91:
    # Set up the stack frame
    addiu   $sp,$sp,-32
    sw      $31,28($sp)
    sw      $fp,24($sp)
    move    $fp,$sp

    # Check if we want case 1 or case 2
    slt     $2,$4,101
    bne     $2,$0,$L2
    nop                 # Delay slot

    # Case 1: n > 100 -> M(n) := n - 10
    addiu   $2,$4,-10
    b       $L3
    nop                 # Delay slot
$L2:
    # Case 2: n <= 100 -> M(n) := M(M(n + 11)
    addiu   $4,$4,11
    jal     mc91
    nop                 # Delay slot
    move    $4,$2
    jal     mc91
    nop                 # Delay slot
$L3:
    # Clean up the stack and return
    move    $sp,$fp
    lw      $31,28($sp)
    lw      $fp,24($sp)
    addiu   $sp,$sp,32
    jr      $31
    nop                 # Delay slot
