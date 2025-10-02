    .text
_start:
    bl      main

strlen:
    move    $t0,$a0
    li.w    $a0,0

.L2:
    ld.b    $t1,$t0,0
    beq     $t1,$zero,.L3

    addi.w  $a0,$a0,1
    addi.d  $t0,$t0,1

    b       .L2

.L3:
    ret

main:
    bl      strlen
    nop
