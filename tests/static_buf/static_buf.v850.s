    .text
foobar:
    .long   0
test:
    jarl    foobar, lp
    ld.w    0[r10], r10     # load through the address the model returned
