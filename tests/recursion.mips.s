    .text
_start:
mc91:
    # Avoid MIPS messing with delay slots.
    # I know what I want, dammit!
    .set    noreorder
    .set    nomacro
    # Set up the stack frame
    addiu   $sp,$sp,-32
    sw      $ra,28($sp)
    sw      $fp,24($sp)
    move    $fp,$sp

    # Check if we want case 1 or case 2
    slt     $v0,$a0,101
    bne     $v0,$zero,.L2
    nop                 # Delay slot

    # Case 1: n > 100 -> M(n) := n - 10
    b       .L3
    addiu   $v0,$a0,-10 # Delay slot

.L2:
    # Case 2: n <= 100 -> M(n) := M(M(n + 11)
    bal     mc91
    addiu   $a0,$a0,11  # Delay slot

    bal     mc91
    move    $a0,$v0     # Delay slot
.L3:
    # Clean up the stack and return
    move    $sp,$fp
    lw      $ra,28($sp)
    lw      $fp,24($sp)
    addiu   $sp,$sp,32
    jr      $ra
    nop                 # Delay slot
