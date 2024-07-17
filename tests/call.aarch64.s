    .text
_start:
        bl      foo
bar:
        mov     w1, 8
        mul     w1, w0, w1
        cmp     w0, 101
        mov     w0, w1
        b.lt    .L2
        mov     w0, 32
.L2:
        ret 
foo:
        sub     x0, x0, 1
        bl      bar
        add     x0, x0, 1
