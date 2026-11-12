    .text
test:
    ! Put the status register into a fully known state before anything reads the
    ! T bit.  SH-1/SH-2's sleigh model has no standalone T register - T is the
    ! bitfield sr[0,1] - so a symbolic-state backend that starts with sr
    ! unconstrained would otherwise carry that symbol through tst/movt into the
    ! result.  Writing the whole register makes every bit concrete; `clrt` alone
    ! is not enough, because a deposit into a symbolic sr stays symbolic.
    !
    ! Only clearing T matters here.  SH-1 and SH-2 have no SR.MD, and bit 30 is
    ! reserved; 0x40000000 sets it only so this code is the same as the other
    ! SuperH versions'.
    mov     #0x40, r1
    shll16  r1
    shll8   r1
    ldc     r1, sr
    ! Return 1 if the argument (r4) equals 100, else 0.
    !
    ! SuperH has no compare-into-register: comparisons land in the T bit, and
    ! movt copies T into a general-purpose register.  tst Rm,Rn sets T when
    ! (Rm & Rn) == 0, so tst r4,r4 is the idiomatic "is r4 zero?".
    add     #-100, r4
    tst     r4, r4
    movt    r0
