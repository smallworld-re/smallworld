    .text
_start:
    ba      main
     nop
mc91:
    ! McCarthy 91, with a register window per call.
    save    %sp, -96, %sp

    ! Check if we want case 1 or case 2
    cmp     %i0, 100
    ble     .L2
     nop

    ! Case 1: n > 100 -> M(n) := n - 10
    ba      .L3
     sub    %i0, 10, %i0
.L2:
    ! Case 2: n <= 100 -> M(n) := M(M(n + 11))
    call    mc91
     add    %i0, 11, %o0
    call    mc91
     nop
    mov     %o0, %i0
.L3:
    ret
     restore
main:
    call    mc91
     nop
