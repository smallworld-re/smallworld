    .text
test:
    ! Return 1 if the argument (%o0) is 100, else 0
    cmp     %o0, 100
    bne     .L2
     nop
    ba      .L3
     mov    1, %o0
.L2:
    mov     0, %o0
.L3:
    nop
