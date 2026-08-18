    .text
_start:
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
