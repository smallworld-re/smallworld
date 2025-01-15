    .text
test:
    # This returns 1 if arg1 is 100, 0 otherwise
    movi    $a3, 100
    bne     $a2, $a3, .L2
    movi    $a2, 0x1
    j       .L3
.L2:
    movi    $a2, 0x0
.L3:
    nop
