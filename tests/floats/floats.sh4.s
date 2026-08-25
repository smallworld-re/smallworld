    .text
test:
    ! Add the two floating-point arguments, leaving the result in fr0.
    !
    ! Single precision, deliberately: SuperH selects precision from FPSCR.PR
    ! rather than from the opcode, so the harness sets FPSCR to 0x00040000
    ! (PR=0, round-to-nearest) before entry.  The double-precision path is
    ! measurably broken on Styx for SuperH, and this scenario only asserts a
    ! "3.3" prefix, which single precision satisfies.
    !
    ! fr0 and fr2 rather than fr0 and fr1: fr0/fr1 are the two halves of dr0,
    ! so a harness setting both would be writing one register twice.  fr2 lives
    ! in dr2, which keeps the two operands independent.
    fadd    fr2, fr0
