    .text
    .set    noreorder
    .set    nomacro
strlen:
    li      $2,0
.L2:
    lb      $3,($4)
    beq     $3,$0,.L3
    nop
    addiu   $2,$2,1
    addiu   $4,$4,1
    b       .L2
    nop
.L3:
    jr      $31
    nop
    
