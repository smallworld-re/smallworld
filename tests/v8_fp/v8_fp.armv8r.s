    .syntax unified
    .arm
    .text
    @ ARMv8 floating point, with ties deciding every rounding:
    @   s0 = arg + 0.5, a tie
    @   s1 = vrinta(s0), rounding ties away
    @   s3 = vmaxnm(s1, 7.0), IEEE maxNum
    @   s4 = arg == 5 ? s3 : s0 (vseleq)
    @ and returns vcvta(s4) in bits 7:0 and vcvta(s1) in bits 15:8, both
    @ rounding ties away.
    @ arg 5 -> 0x0607; arg 2 -> 0x0303; arg -3 -> 0xfdfd.
fp:
    vmov            s0, r0
    vcvt.f32.s32    s0, s0
    vmov.f32        s5, #0.5
    vadd.f32        s0, s0, s5
    vrinta.f32      s1, s0
    vmov.f32        s2, #7.0
    vmaxnm.f32      s3, s1, s2
    cmp             r0, #5
    vseleq.f32      s4, s3, s0
    vcvta.s32.f32   s4, s4
    vcvta.s32.f32   s6, s1
    vmov            r0, s4
    vmov            r1, s6
    uxtb            r0, r0
    uxtb            r1, r1
    orr             r0, r0, r1, lsl #8
