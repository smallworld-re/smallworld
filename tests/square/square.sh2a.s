    .text
square:
    ! Square the first argument (r4)
    ! and save the result to the return register (r0).
    !
    ! Same sequence as the SH-4 version: mul.l leaves the low 32 bits of the
    ! product in MACL, and sts moves it into r0.  SH-2A also has `mulr r0,Rn`,
    ! which multiplies straight into a general-purpose register, but this test
    ! exists to check the shared arithmetic path rather than the SH-2A additions.
    mul.l   r4, r4
    sts     macl, r0
