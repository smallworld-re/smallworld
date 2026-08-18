    .text
_start:
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
