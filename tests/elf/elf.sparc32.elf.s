    .text
    .globl  _start
    .type   _start, #function
_start:
    ! Load argc; if argc != 2, fail
    ld      [%sp], %o0
    cmp     %o0, 2
    bne     .L2
     nop

    ! Load argv, then argv[1]
    ld      [%sp + 4], %o1
    ld      [%o1 + 4], %o1

    ! for (i = 0; argv[1][i] != '\0'; i++);
    mov     0, %o0
.L3:
    ldub    [%o1 + %o0], %o2
    cmp     %o2, 0
    bne,a   .L3
     add    %o0, 1, %o0     ! annulled: only runs when the branch is taken
    retl
     nop

.L2:
    ! Failed; return -1
    retl
     mov    -1, %o0
