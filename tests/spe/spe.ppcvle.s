    .text
# Single-precision arithmetic with the SPE embedded floating-point
# instructions, which e200 cores with floating point have in place of a
# classic FPU. They work on the general-purpose registers. Returns trunc(n * n / 2 - 10) for n in r3.
spe:
    efscfsi  3,3        # r3 = (float)n
    efsmul   3,3,3      # r3 = n * n
    se_li    4,2
    efscfsi  4,4        # r4 = 2.0
    efsdiv   3,3,4      # r3 = n * n / 2
    se_li    4,10
    efscfsi  4,4        # r4 = 10.0
    efssub   3,3,4      # r3 = n * n / 2 - 10
    efsctsiz 3,3        # r3 = (int)r3, rounding toward zero
