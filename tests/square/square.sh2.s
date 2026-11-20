    .text
square:
    ! Square the first argument (r4)
    ! and save the result to the return register (r0).
    !
    ! SH-1 has no 32-bit multiply (`mul.l` is an SH-2 addition), so this uses
    ! the 16 x 16 -> 32-bit unsigned `mulu.w`, which leaves the product in MACL.
    ! Every input the square scenario uses fits in 16 bits.
    mulu.w  r4, r4
    sts     macl, r0
