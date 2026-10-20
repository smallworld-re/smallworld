    .text
# Fake the PLT
foobar:
    ebreak
test:
    # Set up the stack
    addi    t0, sp, -4
    sw      ra, 0x0(sp)

    # int *ret = foobar();
    jal     ra, foobar

    # return *ret;
    lw      a0, 0x0(a0)

    # Clean up the stack
    lw      ra, 0x0(sp)
    addi    sp, sp, 4
