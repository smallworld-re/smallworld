    .text
# Fake the PLT
foobar:
    ebreak
test:
    # Set up the stack
    addiw   t0, sp, -8
    sd      ra, 0x0(sp)

    # int *ret = foobar();
    jal     ra, foobar

    # return *ret;
    ld      a0, 0x0(a0)

    # Clean up the stack
    ld      ra, 0x0(sp)
    addi    sp, sp, 8
