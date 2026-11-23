    @ Berkeley TestFloat kernels for ARMv7E-M with FPv4-SP (armv7em, hard-float).
    @
    @ The same contract and layout as testfloat.armv7a.s, in Thumb: four entry
    @ points at fixed offsets, the arithmetic instruction of each loop patched
    @ in by the harness, every loop leaving through `done` at 0x100.
    @
    @ FPv4-SP is single-precision only, so the two f64 entry points just leave;
    @ the harness skips the f64 functions on this architecture.
    @
    @ None of the armv7a prologue is needed: the M profile has no FPEXC (its
    @ FPU is gated by the memory-mapped CPACR instead), and Unicorn's Cortex-M4
    @ comes out of reset with the FPU enabled. FPSCR still comes from r3,
    @ installed by guest code.
    .eabi_attribute 28, 1
    .text
    .syntax unified
    .thumb

    .org 0x00
f32_binary:
    vmsr    fpscr, r3
.Lf32_binary:
    vldr    s0, [r0]                @ operand a
    vldr    s1, [r0, #4]            @ operand b
    adds    r0, r0, #8
    vadd.f32 s0, s0, s1             @ PATCHED: vadd/vsub/vmul/vdiv
    vstr    s0, [r1]
    adds    r1, r1, #4
    subs    r2, r2, #1
    bne     .Lf32_binary
    b       done

    .org 0x40
f32_unary:
    vmsr    fpscr, r3
.Lf32_unary:
    vldr    s0, [r0]
    adds    r0, r0, #4
    vsqrt.f32 s0, s0                @ PATCHED: vsqrt/vabs/vneg
    vstr    s0, [r1]
    adds    r1, r1, #4
    subs    r2, r2, #1
    bne     .Lf32_unary
    b       done

    .org 0x80
f64_binary:
    b       done

    .org 0xC0
f64_unary:
    b       done

    .org 0x100
done:
    nop
