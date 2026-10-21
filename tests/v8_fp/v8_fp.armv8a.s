    .syntax unified
    .arm
    .text
    @ ARMv8 floating point: round arg + 0.5 to nearest, ties away (vrinta),
    @ take the IEEE maxNum of that and 3.0 (vmaxnm), keep it only if arg is 5
    @ (vseleq; 3.0 otherwise), and convert to an integer rounding ties away
    @ (vcvta). arg 5 -> 6; arg 2 -> 3.
fp:
    vmov            s0, r0
    vcvt.f32.s32    s0, s0
    vmov.f32        s5, #0.5
    vadd.f32        s0, s0, s5
    vrinta.f32      s0, s0
    vmov.f32        s1, #3.0
    vmaxnm.f32      s2, s0, s1
    cmp             r0, #5
    vseleq.f32      s3, s2, s1
    vcvta.s32.f32   s4, s3
    vmov            r0, s4
