    .text
    ! SH-2A-FPU single-precision coverage.
    !
    ! The "-FPU" in SH2A-FPU is the whole reason this platform is distinct from
    ! plain SH-2A, and until this scenario existed the suite exercised exactly one
    ! floating-point instruction.  Every operand here is chosen so the result is
    ! exactly representable in IEEE-754 binary32, so the expected values are
    ! asserted as exact bit patterns and no rounding mode can change them.
    !
    ! SuperH selects precision from FPSCR.PR at *runtime*, not from the opcode -
    ! `fadd fr1,fr4` and `fadd dr2,dr8` assemble to the same encoding shape.  The
    ! runner therefore sets FPSCR = 0x00040001 (PR=0 single, SZ=0, DN=1) before
    ! entry, and the sh2a_fpu_double scenario runs the double-precision path.
    !
    ! Inputs, set by the runner:  fr0 = 1.5   fr1 = 2.25   fr2 = 0.5   fr3 = 4.0
    ! Every operation copies its input first, so the inputs stay intact and each
    ! result lands in its own register - a backend that corrupts a neighbouring
    ! floating-point register is then visible rather than masked.
sh2a_fpu:
    ! *** Arithmetic ***
    fmov    fr0, fr4
    fadd    fr1, fr4            ! fr4  =  1.5 + 2.25 =  3.75
    fmov    fr0, fr5
    fsub    fr1, fr5            ! fr5  =  1.5 - 2.25 = -0.75
    fmov    fr0, fr6
    fmul    fr1, fr6            ! fr6  =  1.5 * 2.25 =  3.375
    fmov    fr3, fr7
    fdiv    fr2, fr7            ! fr7  =  4.0 / 0.5  =  8.0
    fmov    fr3, fr8
    fsqrt   fr8                 ! fr8  =  sqrt(4.0)  =  2.0

    ! *** Sign manipulation ***
    fmov    fr0, fr9
    fneg    fr9                 ! fr9  = -1.5
    fmov    fr5, fr10
    fabs    fr10                ! fr10 =  |-0.75|    =  0.75

    ! *** Immediate loads ***
    ! fldi0/fldi1 are the only way to materialise a float without a memory
    ! access; they exist precisely because SuperH has no FP immediate form.
    fldi0   fr11                ! fr11 =  0.0
    fldi1   fr12                ! fr12 =  1.0

    ! *** Multiply-accumulate ***
    ! fmac's first operand is fixed at FR0 by the encoding: FR0*FRm + FRn -> FRn.
    fmov    fr2, fr13
    fmac    fr0, fr1, fr13      ! fr13 =  1.5 * 2.25 + 0.5 = 3.875

    ! *** Integer conversion, both directions, through FPUL ***
    ! ftrc truncates toward zero regardless of FPSCR.RM, so 3.75 -> 3.
    ftrc    fr4, fpul
    sts     fpul, r1            ! r1   =  3
    mov     #7, r2
    lds     r2, fpul
    float   fpul, fr15          ! fr15 =  7.0

    ! *** Raw bit moves through FPUL ***
    ! flds/fsts move bits without conversion, so fr14 ends up bit-identical to
    ! fr1 (2.25).  A backend that routes these through a float conversion, or
    ! that keeps FPUL as anything other than a raw 32-bit slot, diverges here.
    flds    fr1, fpul
    fsts    fpul, fr14          ! fr14 =  2.25, bit-for-bit
