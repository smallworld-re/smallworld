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
    addiu   $sp,$sp,-32
    sw      $ra,28($sp)
    sw      $fp,24($sp)
    move    $fp,$sp
    
    bal     bar
    addi    $a0,$a0,-1      # Delay slot
    addi    $v0,$v0,1
