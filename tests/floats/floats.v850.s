    .text
test:
    # Add the two single-precision arguments in r6 and r7, leaving the result
    # in r10. V850E2M's FPU computes on the general registers.
    #
    # The FPU is a V850E2M (V850E2V3) addition, and the Makefile assembles
    # V850 tests for V850E1, so select the later core for this file only.
    .v850e2v3
    addf.s  r6, r7, r10
