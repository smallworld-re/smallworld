    ! Berkeley TestFloat kernels for SH-4, big- and little-endian.
    !
    ! Byte-identical in intent to the SH-2A kernels: every instruction here is
    ! SH-2 or SH-2E base, so one source serves both SH-4 endiannesses via
    ! SH4EL_SRC_EXT.  Kept as a separate file rather than shared with the SH-2A
    ! source so the two generations can diverge without silently coupling.
    !
    ! Four loops, one per (precision, arity), each at a fixed offset so the
    ! harness can pick an entry point without parsing the binary.  The
    ! arithmetic instruction of each loop is patched in by the harness - every
    ! SuperH FP op shares the encoding shape 1111 nnnn mmmm iiii, so fadd/fsub/
    ! fmul/fdiv differ only in the low nibble - which keeps this to one source
    ! file per architecture instead of one per operation.
    !
    ! Contract (identical on every architecture):
    !   r4 = input base, r5 = output base, r6 = case count (> 0), r7 = FPSCR
    !   inputs are packed operands, big-endian, no padding
    !   each iteration writes one result to the output cursor
    !   every loop leaves via the shared `done` label at offset 0x100
    !
    ! Each loop begins by loading FPSCR from r7 rather than trusting the harness
    ! to have poked the register.  Ghidra's SuperH4 sleigh keeps PR/SZ/RM in
    ! separate one-byte pseudo-registers that only splitFPSCRregister() - which
    ! runs inside `lds Rm,FPSCR` - refreshes, so a direct register write leaves
    ! them stale and every double-precision op silently runs single.
    !
    ! FPSCR value comes from the harness: TestFloat compares against
    ! round-to-nearest-even with denormals live, so RM must be 00 and DN 0 -
    ! which is *not* the SuperH reset state.
    .text

    .org 0x00
f32_binary:
    lds     r7, fpscr
.Lf32_binary:
    fmov.s  @r4+, fr0               ! operand a
    fmov.s  @r4+, fr1               ! operand b
    fadd    fr1, fr0                ! PATCHED: fadd/fsub/fmul/fdiv
    fmov.s  fr0, @r5
    add     #4, r5
    dt      r6
    bf      .Lf32_binary
    bra     done
    nop                             ! delay slot

    .org 0x40
f32_unary:
    lds     r7, fpscr
.Lf32_unary:
    fmov.s  @r4+, fr0
    fsqrt   fr0                     ! PATCHED: fsqrt/fabs/fneg
    fmov.s  fr0, @r5
    add     #4, r5
    dt      r6
    bf      .Lf32_unary
    bra     done
    nop

    .org 0x80
f64_binary:
    lds     r7, fpscr
.Lf64_binary:
    fmov.d  @r4+, dr0
    fmov.d  @r4+, dr2
    fadd    dr2, dr0                ! PATCHED
    fmov.d  dr0, @r5
    add     #8, r5
    dt      r6
    bf      .Lf64_binary
    bra     done
    nop

    .org 0xC0
f64_unary:
    lds     r7, fpscr
.Lf64_unary:
    fmov.d  @r4+, dr0
    fsqrt   dr0                     ! PATCHED
    fmov.d  dr0, @r5
    add     #8, r5
    dt      r6
    bf      .Lf64_unary
    bra     done
    nop

    .org 0x100
done:
    nop
