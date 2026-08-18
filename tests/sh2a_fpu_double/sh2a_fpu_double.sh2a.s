    .text
    ! SH-2A-FPU double-precision coverage.
    !
    ! Precision is selected by FPSCR.PR at runtime, not by the opcode: every
    ! instruction below assembles to the same encoding as its single-precision
    ! spelling, and objdump prints them all as `fadd fr...` regardless.  The
    ! runner sets FPSCR = 0x000c0001 (PR=1 double, SZ=0, DN=1, RM=round-to-zero)
    ! before entry, which is the only thing that makes this the double path.
    ! That also makes this blob a useful differential probe: the identical bytes
    ! must produce different results under the two FPSCR settings.
    !
    ! Only dr0/dr2/.../dr14 exist in double mode, and all eight are in use, so
    ! the fcnvsd/fcnvds round trip lives in sh2a_fpu_overlay instead.
    !
    ! Deliberately no register-to-register `fmov`: that instruction's transfer
    ! width comes from FPSCR.SZ rather than PR, so a 64-bit move would need
    ! SZ=1 and would conflate two orthogonal FPSCR bits in one test.  Every
    ! operand is placed by the runner instead.
    !
    ! Inputs, set by the runner:
    !   dr0 = 1.5    dr2 = 2.25   dr4 = 0.5    dr6  = 4.0
    !   dr8 = 1.5    dr10 = 1.5   dr12 = -0.75 dr14 = 4.0
sh2a_fpu_double:
    ! *** Arithmetic ***
    ! dr8 is chained deliberately - fadd then fmul - because 3.75 * 2.25 =
    ! 8.4375 is still exactly representable, so a chained result costs no
    ! precision while covering two instructions in one register.
    fadd    dr2, dr8            ! dr8  = 1.5 + 2.25   = 3.75
    fmul    dr2, dr8            ! dr8  = 3.75 * 2.25  = 8.4375
    fsub    dr2, dr10           ! dr10 = 1.5 - 2.25   = -0.75
    fdiv    dr4, dr14           ! dr14 = 4.0 / 0.5    = 8.0
    fsqrt   dr6                 ! dr6  = sqrt(4.0)    = 2.0

    ! *** Sign manipulation ***
    fneg    dr0                 ! dr0  = -1.5
    fabs    dr12                ! dr12 = |-0.75|      = 0.75

    ! *** Integer conversion, both directions, through FPUL ***
    ! FPUL stays 32-bit even in double mode: ftrc narrows to an integer and
    ! float widens from one.  Ordered after the fdiv above so dr14 holds 8.0,
    ! and after it so overwriting dr4 cannot disturb the divisor.
    ftrc    dr14, fpul          ! fpul = trunc(8.0)   = 8
    sts     fpul, r1            ! r1   = 8
    mov     #9, r2
    lds     r2, fpul
    float   fpul, dr4           ! dr4  = 9.0

    ! *** Comparison ***
    ! Each fcmp writes T before the movt that reads it, so no SR preamble is
    ! needed.  This blob deliberately never executes `ldc Rm,SR`: that would
    ! clear SR.MD and drop a full-system backend into user mode.
    fcmp/eq dr2, dr2            ! T = (dr2 == dr2)    = 1
    movt    r3                  ! r3 = 1
    fcmp/gt dr0, dr2            ! T = (dr2 >  dr0)    = (2.25 > -1.5) = 1
    movt    r4                  ! r4 = 1
    fcmp/gt dr2, dr0            ! T = (dr0 >  dr2)    = (-1.5 > 2.25) = 0
    movt    r5                  ! r5 = 0
