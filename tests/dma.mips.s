    .text
divide:
    li      $t0,0x50010000
    ori     $t0,$t0,0x4000
    sw      $a0,($t0)
    sw      $a1,4($t0)
    lw      $v0,8($t0)
