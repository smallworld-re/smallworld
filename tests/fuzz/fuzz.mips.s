    .text
    .set    noreorder
    .set    nomacro
vuln:
    lw      $t0, 0($a0)
    slti    $t0, $t0,12
    bnez    $t0, .L3
    nop
    lb      $t0, 4($a0)
    li      $t1, 98
    beq     $t0, $t1,.L2
    nop
.L1:
    li      $v0, 0
    b       .L4
    nop
.L2:
    lb      $t0, 5($a0)
    li      $t1, 97
    bne     $t0, $t1, .L3
    nop
    lb      $t0, 6($a0)
    li      $t1, 100
    bne     $t0, $t1, .L3
    nop
    lb      $t0, 7($a0)
    li      $t1, 33
    bne     $t0, $t1, .L3
    nop
    lb      $t0, 8($a0)
    lui     $t1, 0x1234
    ori     $t1, $t1, 0x5678
    sw      $t0, 0($t1)
.L3:
    li      $v0, -1
.L4:
    nop
