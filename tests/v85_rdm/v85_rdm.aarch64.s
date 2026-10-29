    .arch armv8.5-a
    .text
    // ARMv8.1 RDM: sqrdmlah accumulates the rounded doubling high half of
    // arg * 0x40000000 into 5, in each 32-bit lane. Returns lane 0.
rdm:
    dup     v1.4s, w0
    movi    v2.4s, #0x40, lsl #24
    movi    v0.4s, #5
    sqrdmlah v0.4s, v1.4s, v2.4s
    umov    w0, v0.s[0]
