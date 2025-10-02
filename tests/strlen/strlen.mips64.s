    .text
    .set    noreorder
    .set    nomacro
_start:
    bal     main
    nop                     # Delay slot
strlen:
    li      $2,0
.L2:
    lb      $3,($4)
    beq     $3,$0,.L3
    nop                     # Delay slot

    addiu   $2,$2,1
    daddiu  $4,$4,1
    b       .L2
    nop                     # Delay slot
.L3:
    jr      $31
    nop                     # Delay slot
main:
    bal     strlen
    nop                     # Delay slot
    nop
