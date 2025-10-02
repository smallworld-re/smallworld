    .text
_start:
        bl      foo
bar:
        push    {fp, lr}
        mov     r1, #8
        mul     r1, r0, r1
        cmp     r0, #101
        mov     r0, r1
        blt     .L2
        mov     r0, #32
.L2:
        pop     {fp, pc}
foo:
        sub     r0, r0, #1
        bl      bar
        add     r0, r0, #1
        nop
