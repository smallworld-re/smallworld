    .text
square:
    ! Square the first argument (r4)
    ! and save the result to the return register (r0).
    !
    ! SuperH has no 32x32->32 multiply that writes a general-purpose register:
    ! mul.l leaves the low 32 bits of the product in MACL, so read it back out.
    mul.l   r4, r4
    sts     macl, r0
