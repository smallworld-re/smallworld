    .text
foobar:
    .word   0
test:
    call    foobar
    ld.w    %d2, [%a2]0
