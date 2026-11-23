    .arch armv8.5-a
    .text
    // ARMv8.3 RCpc and ARMv8.4 LRCPC2: store-release the argument, then load
    // it back with ldapr and the unscaled ldapur. Returns 2 * arg.
rcpc:
    sub     sp, sp, #16
    mov     x1, sp
    stlr    x0, [x1]
    ldapr   x2, [x1]
    stlur   x0, [x1, #8]
    ldapur  x3, [x1, #8]
    add     x0, x2, x3
    add     sp, sp, #16
