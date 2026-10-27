    # Berkeley TestFloat kernels for PowerPC (big-endian; the ppc source is identical).
    #
    # Four loops, one per (precision, arity), each at a fixed offset so the
    # harness can pick an entry point without parsing the binary.  The
    # arithmetic instruction of each loop is patched in by the harness.  The
    # A-form floating-point word is
    #   primary[0:5] | FRT | FRA | FRB | FRC | XO[26:30] | Rc
    # where the primary opcode picks single (59) from double (63) and XO picks
    # the operation, so one source file covers every operation.
    #
    # Contract (identical on every architecture):
    #   r3 = input base, r4 = output base, r5 = case count (> 0)
    #   inputs are packed operands, big-endian, no padding
    #   each iteration writes one result to the output cursor
    #   every loop leaves via the shared `done` label at offset 0x100
    #
    # Each loop opens by installing the FPSCR mode TestFloat verifies against,
    # rather than trusting the reset value: `mtfsfi 6,0` clears the VE/OE/UE/ZE
    # enables and `mtfsfi 7,0` clears XE, NI (non-IEEE mode, which would flush
    # subnormals) and RN (00, round to nearest with ties to even).  The case
    # count goes into CTR, so the loop counts down with `bdnz` and never touches
    # CR, which a patched instruction could otherwise be read as depending on.
    #
    # Single precision loads with `lfs`, which widens to double exactly, and
    # stores with `stfs`, which narrows exactly because the single-precision
    # operation (`fadds` and friends) has already rounded the result.  All
    # instructions are four bytes, so the patch offsets are entry+20 (two
    # mtfsfi, mtctr, two loads) and entry+16 (one load).
    .text

    .org 0x00
f32_binary:
    mtfsfi  6,0
    mtfsfi  7,0
    mtctr   5
.Lf32_binary:
    lfs     0,0(3)              # operand a
    lfs     1,4(3)              # operand b
    fadds   0,0,1               # PATCHED: fadds/fsubs/fmuls/fdivs
    stfs    0,0(4)
    addi    3,3,8
    addi    4,4,4
    bdnz    .Lf32_binary
    b       done

    .org 0x40
f32_unary:
    mtfsfi  6,0
    mtfsfi  7,0
    mtctr   5
.Lf32_unary:
    lfs     0,0(3)
    fsqrts  0,0                 # PATCHED: fsqrts/fabs/fneg
    stfs    0,0(4)
    addi    3,3,4
    addi    4,4,4
    bdnz    .Lf32_unary
    b       done

    .org 0x80
f64_binary:
    mtfsfi  6,0
    mtfsfi  7,0
    mtctr   5
.Lf64_binary:
    lfd     0,0(3)
    lfd     1,8(3)
    fadd    0,0,1               # PATCHED: fadd/fsub/fmul/fdiv
    stfd    0,0(4)
    addi    3,3,16
    addi    4,4,8
    bdnz    .Lf64_binary
    b       done

    .org 0xC0
f64_unary:
    mtfsfi  6,0
    mtfsfi  7,0
    mtctr   5
.Lf64_unary:
    lfd     0,0(3)
    fsqrt   0,0                 # PATCHED: fsqrt/fabs/fneg
    stfd    0,0(4)
    addi    3,3,8
    addi    4,4,8
    bdnz    .Lf64_unary
    b       done

    .org 0x100
done:
    nop
