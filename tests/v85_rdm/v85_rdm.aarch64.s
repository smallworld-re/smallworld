    .arch armv8.5-a
    .text
    // ARMv8.1 RDM: sqrdmlah accumulates the rounded doubling high half of
    // arg * 0x40000000 into 5, in each 32-bit lane. Then the scalar sqrdmlsh
    // subtracts the high half of arg * INT32_MIN, taken from lane 1 of a
    // register whose lane 0 differs, which saturates for a large arg.
    // Returns lane 0.
rdm:
    dup     v1.4s, w0
    movi    v2.4s, #0x40, lsl #24
    movi    v0.4s, #5
    sqrdmlah v0.4s, v1.4s, v2.4s
    mov     w1, #0x80000000
    mov     v2.s[1], w1
    sqrdmlsh s0, s1, v2.s[1]
    umov    w0, v0.s[0]
