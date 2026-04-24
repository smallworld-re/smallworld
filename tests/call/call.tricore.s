    .text
bar:
    lt      %d2, %d4, 101
    jnz     %d2, .Lsmall
    mov     %d2, 32
    ret     #bar
.Lsmall:
    mov     %d2, %d4
    sh      %d2, 3
    ret     #bar

foo:
    add     %d4, -1
    call    bar
    add     %d2, 1
