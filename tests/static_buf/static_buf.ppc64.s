    .text
# Fake the PLT
foobar:
    trap
test:
    # Set up the stack
    mflr    0           # Move link register to r0
    std     0,16(1)     # Store link address to sp + 16
    std     31,-8(1)    # Store base pointer to sp - 8
    stdu    1,-224(1)   # No idea.
    mr      31,1        # Move sp to bp

    # int *ret = foobar();
    bl      foobar

    # return *ret;
    lwz     3,0(3)

    # Clean up the stack
    addi    1,31,224
    ld      0,16(1)
    mtlr    0
    ld      31,-8(1)
