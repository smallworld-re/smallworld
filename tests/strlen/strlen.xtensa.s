    .text
_start:
    call0   main
.byte 0x00

strlen:
    movi    $a3, 0x0
.L0:
    l8ui    $a4, $a2, 0
    beqz    $a4, .L1
    addi    $a2, $a2, 1
    addi    $a3, $a3, 1
    j       .L0
.L1:
    mov     $a2, $a3
    ret
    
main:
    call0   strlen

    nop
