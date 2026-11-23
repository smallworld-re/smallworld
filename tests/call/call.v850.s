    .text
bar:
    movea   101, r0, r11
    cmp     r11, r6
    blt     .Lsmall
    movea   32, r0, r10
    jmp     [lp]
.Lsmall:
    mov     r6, r10
    shl     3, r10
    jmp     [lp]
foo:
    add     -1, r6
    jarl    bar, lp
    add     1, r10
