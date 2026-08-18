    .text
test:
    ! Return 1 if the argument (r4) equals 100, else 0.
    !
    ! SuperH has no compare-into-register: comparisons land in the T bit, and
    ! movt copies T into a general-purpose register.  tst Rm,Rn sets T when
    ! (Rm & Rn) == 0, so tst r4,r4 is the idiomatic "is r4 zero?".
    add     #-100, r4
    tst     r4, r4
    movt    r0
