    .text
_start:
    ba      main
     nop
strlen:
    ! A leaf routine: no window, return with retl
    mov     %o0, %o1
    mov     0, %o0
.L2:
    ldub    [%o1 + %o0], %o2
    cmp     %o2, 0
    bne,a   .L2
     add    %o0, 1, %o0     ! annulled: only runs when the branch is taken
    retl
     nop
main:
    call    strlen
     nop
