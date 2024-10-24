    .text
    .set    noreorder
    .set    nomacro
    .set    nomips16
    .set    nomicromips
_start:
    bal     foo
    nop
bar:
    addiu   $t0,$zero,8
    mult    $a0,$t0
    mflo    $v0
    slt     $a0,$a0,101
    bne     $a0,$zero,.L2
    nop                     # Delay slot
    addiu   $v0,$zero,32 
.L2:
    jr      $ra
    nop                     # Delay slot

foo:
    addiu   $sp,$sp,-32
    sw      $ra,28($sp)
    sw      $fp,24($sp)
    move    $fp,$sp
    
    addi    $a0,$a0,-1      # Delay slot
    bal     bar
    nop
    addi    $v0,$v0,1
