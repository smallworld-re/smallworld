    .text
test:
    addiu   $4,$4,-100
    bne     $4,0,$L2
    nop
    li      $2,1
    b       $L3
    nop
$L2:
    li      $2,0
$L3:
    nop
