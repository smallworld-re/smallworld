    .text
_start:
    ! Put the status register into a fully known state before anything reads the
    ! T bit.  SH-2A's sleigh model has no standalone T register - T is the
    ! bitfield sr[0,1] - so a symbolic-state backend that starts with sr
    ! unconstrained would otherwise carry that symbol through tst/movt into the
    ! result.  Writing the whole register makes every bit concrete; `clrt` alone
    ! is not enough, because a deposit into a symbolic sr stays symbolic.
    !
    ! The value matters: 0x40000000 sets SR.MD (bit 30) and clears T.  Writing
    ! plain 0 would clear MD too, dropping a full-system emulator into user mode
    ! where the next privileged instruction faults.
    mov     #0x40, r1
    shll16  r1
    shll8   r1
    ldc     r1, sr
    bsr     main
    nop          ! Delay slot
strlen:
    mov     #0, r0
.Lloop:
    ! mov.b sign-extends, which is fine here: we only test against zero.
    mov.b   @r4, r1
    tst     r1, r1
    bt      .Ldone
    add     #1, r0
    add     #1, r4
    bra     .Lloop
    nop          ! Delay slot
.Ldone:
    rts
    nop          ! Delay slot
main:
    ! bsr leaves the address after this delay slot in pr, which is the end of
    ! the blob - so strlen's rts lands on the harness exit point.
    bsr     strlen
    nop          ! Delay slot
