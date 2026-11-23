    .text
test:
    clr.l   %d0
    mova.l  %d0, %a0
    jmp     (%a0)
    nop
