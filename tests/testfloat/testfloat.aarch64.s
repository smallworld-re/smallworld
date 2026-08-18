    // Berkeley TestFloat kernels for AArch64.
    //
    // Four loops, one per (precision, arity), each at a fixed offset so the
    // harness can pick an entry point without parsing the binary.  The
    // arithmetic instruction of each loop is patched in by the harness.  The
    // scalar two-source FP form is
    //   0001 1110 | type[23:22] | 1 | Rm[20:16] | opcode[15:12] | 10 | Rn | Rd
    // so fadd/fsub/fmul/fdiv differ only in opcode (0010/0011/0000/0001), and
    // the one-source form (FSQRT/FABS/FNEG) differs only in bits [20:15].  In
    // both, type picks single (00) from double (01).  That keeps this to one
    // source file per architecture instead of one per operation.
    //
    // Contract (identical on every architecture):
    //   x0 = input base, x1 = output base, x2 = case count (> 0)
    //   inputs are packed operands, little-endian, no padding
    //   each iteration writes one result to the output cursor
    //   every loop leaves via the shared `done` label at offset 0x100
    //
    // Each loop opens with `msr fpcr, xzr`, which is exactly the mode TestFloat
    // verifies against: RMode = 00 (round to nearest, ties to even), FZ and
    // FZ16 clear so subnormals stay live - with flush-to-zero every subnormal
    // case would be wrong - and DN/AHP clear.  The kernel installs it rather
    // than the harness for two reasons: FPCR's reset value is architecturally
    // UNKNOWN, and angr's AArch64 machdef does not map `fpcr` at all, so a
    // harness-side seed raises UnsupportedRegisterError there.  The `msr` sits
    // outside the loop body, so it costs one instruction per entry.
    //
    // Loop shape is deliberately uniform: post-indexed ldr/str advance the
    // cursors, `sub`/`cbnz` counts down without disturbing NZCV (so a patched
    // instruction can never be read as depending on flags), and every loop
    // exits through the same `b done`.  All AArch64 instructions are four
    // bytes, so the patch offsets are just entry+12 (msr plus two loads) and
    // entry+8 (msr plus one load).
    .text

    .org 0x00
f32_binary:
    msr     fpcr, xzr
.Lf32_binary:
    ldr     s0, [x0], #4            // operand a
    ldr     s1, [x0], #4            // operand b
    fadd    s0, s0, s1              // PATCHED: fadd/fsub/fmul/fdiv
    str     s0, [x1], #4
    sub     x2, x2, #1
    cbnz    x2, .Lf32_binary
    b       done

    .org 0x40
f32_unary:
    msr     fpcr, xzr
.Lf32_unary:
    ldr     s0, [x0], #4
    fsqrt   s0, s0                  // PATCHED: fsqrt/fabs/fneg
    str     s0, [x1], #4
    sub     x2, x2, #1
    cbnz    x2, .Lf32_unary
    b       done

    .org 0x80
f64_binary:
    msr     fpcr, xzr
.Lf64_binary:
    ldr     d0, [x0], #8
    ldr     d1, [x0], #8
    fadd    d0, d0, d1              // PATCHED
    str     d0, [x1], #8
    sub     x2, x2, #1
    cbnz    x2, .Lf64_binary
    b       done

    .org 0xC0
f64_unary:
    msr     fpcr, xzr
.Lf64_unary:
    ldr     d0, [x0], #8
    fsqrt   d0, d0                  // PATCHED
    str     d0, [x1], #8
    sub     x2, x2, #1
    cbnz    x2, .Lf64_unary
    b       done

    .org 0x100
done:
    nop
