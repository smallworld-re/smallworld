    .text
divide:
    li      $t0,0x50010000
    ori     $t0,$t0,0x4000
    sd      $a0,($t0)
    sd      $a1,8($t0)
    ld      $v0,16($t0)
    nop
