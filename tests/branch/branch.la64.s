    .text
test:
    move    $t0, $zero
    li.w    $t1, 100
    bne     $a0, $t1, .L2
    li.w    $a0, 1
    b       .L3
.L2:
    li.w    $a0, 0
.L3:
    nop
