    .arch armv8.5-a
    .text
    // ARMv8.1 LSE atomics on a stack slot holding the argument: ldaddal adds
    // 3 and returns the argument, swpa stores 7 and returns arg + 3, and cas
    // replaces the 7 with 100. Returns arg + (arg + 3) + 100 + 7. ldaddal and
    // swpa are the acquire and release forms compilers emit for C atomics.
lse:
    sub     sp, sp, #16
    str     x0, [sp]
    mov     x1, sp
    mov     x2, #3
    ldaddal x2, x3, [x1]
    mov     x4, #7
    swpa    x4, x5, [x1]
    mov     x6, #7
    mov     x7, #100
    cas     x6, x7, [x1]
    ldr     x8, [x1]
    add     x0, x3, x5
    add     x0, x0, x8
    add     x0, x0, x6
    add     sp, sp, #16
