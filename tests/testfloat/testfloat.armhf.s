    @ Berkeley TestFloat kernels for ARMv7-A with VFPv3 (armhf, hard-float).
    @
    @ Four loops, one per (precision, arity), each at a fixed offset so the
    @ harness can pick an entry point without parsing the binary.  The
    @ arithmetic instruction of each loop is patched in by the harness: every
    @ VFP data-processing op is one 32-bit word whose operation lives in
    @ bits 23:20 plus bit 6, so vadd/vsub/vmul/vdiv/vsqrt differ only in a few
    @ opcode bits with the register fields untouched.  That keeps this to one
    @ source file per architecture instead of one per operation.
    @
    @ Contract (identical on every architecture):
    @   r0 = input base, r1 = output base, r2 = case count (> 0), r3 = FPSCR
    @   r4 is scratch; inputs are packed operands, little-endian, no padding
    @   each iteration writes one result to the output cursor
    @   every loop leaves via the shared `done` label at offset 0x100
    @
    @ Every loop opens with the same four-instruction prologue, which exists
    @ entirely to work around two backend quirks:
    @
    @ 1. FPEXC.EN (bit 30) gates the whole VFP unit, and Unicorn comes out of
    @    reset with it clear - with it clear *every* VFP instruction, loads and
    @    register moves included, aborts as UC_ERR_INSN_INVALID.  Real armhf
    @    userland never notices because the kernel enables VFP before the first
    @    user instruction, so the guest code has to do it here.  FPEXC cannot be
    @    seeded from the harness instead: angr is VEX-backed and archinfo's
    @    ArchARMEL has no `fpexc` register at all.
    @
    @ 2. The `b` to the very next instruction is not dead code.  VEX lifts
    @    `vmsr fpexc, rN` to an empty IMark - and, worse, every VFP instruction
    @    *after* it in the same IRSB also lifts to an empty IMark, so the loop
    @    silently computes nothing and stores zeroes.  Ending the block right
    @    after the FPEXC write confines that to a block with no other VFP
    @    instruction in it.  Verified with pyvex.lift on both arrangements.
    @
    @ FPSCR then comes from r3, again installed by guest code rather than poked
    @ by the harness, matching the SuperH kernel.  TestFloat compares against
    @ round-to-nearest-even with denormals live, so RMode (bits 23:22) must be
    @ 00 and FZ (bit 24, flush-to-zero) must be 0; unlike SuperH there is no
    @ precision bit, since each instruction's `sz` field selects single or
    @ double, so one FPSCR value serves all four loops.
    .arch armv7-a
    .fpu vfpv3-d16
    .text
    .syntax unified
    .arm

    .org 0x00
f32_binary:
    mov     r4, #0x40000000         @ FPEXC.EN
    vmsr    fpexc, r4               @ enable VFP
    b       .Lf32_binary_fpscr      @ end the block before any other VFP op
.Lf32_binary_fpscr:
    vmsr    fpscr, r3
.Lf32_binary:
    vldr    s0, [r0]                @ operand a
    vldr    s1, [r0, #4]            @ operand b
    add     r0, r0, #8
    vadd.f32 s0, s0, s1             @ PATCHED: vadd/vsub/vmul/vdiv
    vstr    s0, [r1]
    add     r1, r1, #4
    subs    r2, r2, #1
    bne     .Lf32_binary
    b       done

    .org 0x40
f32_unary:
    mov     r4, #0x40000000
    vmsr    fpexc, r4
    b       .Lf32_unary_fpscr
.Lf32_unary_fpscr:
    vmsr    fpscr, r3
.Lf32_unary:
    vldr    s0, [r0]
    add     r0, r0, #4
    vsqrt.f32 s0, s0                @ PATCHED: vsqrt/vabs/vneg
    vstr    s0, [r1]
    add     r1, r1, #4
    subs    r2, r2, #1
    bne     .Lf32_unary
    b       done

    .org 0x80
f64_binary:
    mov     r4, #0x40000000
    vmsr    fpexc, r4
    b       .Lf64_binary_fpscr
.Lf64_binary_fpscr:
    vmsr    fpscr, r3
.Lf64_binary:
    vldr    d0, [r0]
    vldr    d1, [r0, #8]
    add     r0, r0, #16
    vadd.f64 d0, d0, d1             @ PATCHED
    vstr    d0, [r1]
    add     r1, r1, #8
    subs    r2, r2, #1
    bne     .Lf64_binary
    b       done

    .org 0xC0
f64_unary:
    mov     r4, #0x40000000
    vmsr    fpexc, r4
    b       .Lf64_unary_fpscr
.Lf64_unary_fpscr:
    vmsr    fpscr, r3
.Lf64_unary:
    vldr    d0, [r0]
    add     r0, r0, #8
    vsqrt.f64 d0, d0                @ PATCHED
    vstr    d0, [r1]
    add     r1, r1, #8
    subs    r2, r2, #1
    bne     .Lf64_unary
    b       done

    .org 0x100
done:
    nop
