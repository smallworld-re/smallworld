    .text
    .globl _start
    .type _start, @function
_start:
    # Return strlen(argv[1]) if argc is 2, and -1 otherwise.
    ld.w    0[sp], r10
    cmp     2, r10
    bne     .Lfail
    ld.w    4[sp], r11
    ld.w    4[r11], r11
    mov     0, r10
.Lloop:
    ld.b    0[r11], r12
    cmp     r0, r12
    be      .Ldone
    add     1, r11
    add     1, r10
    br      .Lloop
.Lfail:
    mov     -1, r10
.Ldone:
    jmp     [lp]
    .size _start, .-_start
