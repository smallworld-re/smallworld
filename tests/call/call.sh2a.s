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
    bsr     foo
    nop          ! Delay slot
bar:
    ! r0 = r4 * 8, then clamp to 32 when r4 >= 101.
    mov     r4, r0
    shll2   r0
    shll    r0
    mov     #101, r1
    cmp/ge  r1, r4          ! T = (r4 >= 101), signed
    bf      .Lbar_done
    mov     #32, r0
.Lbar_done:
    rts
    nop          ! Delay slot
foo:
    ! Like the other per-arch versions of this test, foo never returns: it runs
    ! off the end of the blob into the harness exit point.  pr is saved anyway
    ! so the prologue looks like real compiler output.
    sts.l   pr, @-r15
    add     #-1, r4
    bsr     bar
    nop          ! Delay slot
    add     #1, r0
