    .text
vuln:
    lwz     4, 0(3)
    cmplwi  4, 11
    ble     .L3
    lbz     4, 4(3)
    cmpwi   4, 98
    beq     .L2
.L1:
    li      3, 0
    b       .L4
.L2:
    lbz     4, 5(3)
    cmpwi   4, 97
    bne     .L1
    lbz     4, 6(3)
    cmpwi   4, 100
    bne     .L1
    lbz     4, 7(3)
    cmpwi   4, 33
    bne     .L1
    lbz     4, 8(3)
    lis     5, 0x1234
    ori     5, 5, 0x5678
    stw     4, 0(5)
.L3:
    li      3, -1
.L4:
    nop
