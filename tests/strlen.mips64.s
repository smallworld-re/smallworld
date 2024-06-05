    .text
strlen:
    li      $2,0
.L2:
    lb      $3,($4)
    beq     $3,$0,.L3
    addiu   $2,$2,1
    daddiu  $4,$4,1
    b       .L2
.L3:
    jr      $31
    nop
