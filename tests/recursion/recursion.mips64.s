    .text
_start:
    bal     main
    nop                 # Delay slot
mc91:
    # Set up the stack frame
    daddiu  $sp,$sp,-48
    sd      $31,40($sp)
    sd      $fp,32($sp)
    sd      $28,24($sp)
    move    $fp,$sp

    # Check if we want case 1 or case 2
    sll     $2,$4,0
    slt     $2,$2,101
    bne     $2,$0,.L2
    nop                 # Delay slot

    # Case 1: n > 100 -> M(n) := n - 10
    addiu   $2,$4,-10
    b       .L3
    nop                 # Delay slot

.L2:
    # Case 3: n <= 100 -> M(n) := M(M(n + 11)
    addiu   $4,$4,11
    bal     mc91
    nop                 # Delay slot
    move    $4,$2
    bal     mc91
    nop                 # Delay slot

.L3:
    # Clean up the stack and return
    move    $sp,$fp
    ld      $31,40($sp)
    ld      $fp,32($sp)
    ld      $28,24($sp)
    daddiu  $sp,$sp,48
    jr      $31
    nop                 # Delay slot
main:
    bal     mc91
    nop                 # Delay slot
