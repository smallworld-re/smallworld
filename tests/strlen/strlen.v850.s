    .text
test:
    mov     0, r10
.Lloop:
    ld.b    0[r6], r11
    cmp     r0, r11
    be      .Ldone
    add     1, r6
    add     1, r10
    br      .Lloop
.Ldone:
