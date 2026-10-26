    @ FPv4-SP is single-precision only, so this adds floats rather than the
    @ doubles the A- and R-profile versions use.
    .eabi_attribute 28, 1
    .text
    .syntax unified
    .thumb
test:
    vadd.f32 s0,s0,s1
