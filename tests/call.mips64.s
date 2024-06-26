    .text
    .set    noreorder
    .set    nomacro
_start:
    bal     foo
    nop
bar:
    addiu   $t0,$zero,8
    mult    $a0,$t0
    mflo    $v0
    bne     $a0,$zero,.L2
    slt     $a0,$a0,101     # Delay slot
    addiu   $v0,$zero,32 
.L2:
    jr      $ra
    nop                     # Delay slot

foo:
    daddiu  $sp,$sp,-48
    sd      $ra,40($sp)
    sd      $fp,32($sp)
    sd      $gp,24($sp)
    move    $fp,$sp
    
    bal     bar
    addi    $a0,$a0,-1      # Delay slot
    addi    $v0,$v0,1

    move    $sp,$fp
    ld      $ra,40($sp)
    ld      $fp,32($sp)
    ld      $gp,24($sp)
    daddiu  $sp,$sp,48
