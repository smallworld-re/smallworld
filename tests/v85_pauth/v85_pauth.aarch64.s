    .arch armv8.5-a
    .text
    // ARMv8.3 pointer authentication: sign the argument with key IA and a
    // modifier, then authenticate it, and separately sign and strip it.
    // Both give the argument back, so returns 2 * arg. The branch-protection
    // hints (bti, paciasp, autiasp) sign and check lr in place.
pauth:
    bti     c
    paciasp
    mov     x1, #0x1234
    mov     x2, x0
    pacia   x2, x1
    autia   x2, x1
    mov     x3, x0
    pacia   x3, x1
    xpaci   x3
    add     x0, x2, x3
    autiasp
