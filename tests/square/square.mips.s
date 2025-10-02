    .text
square:
    # Square the first argument ($4)
    # and save the result to the return register ($2)
    # This uses a pseudo-op;
    # it should expand to the exact same code
    # as the mips64 example
    mul $2,$4,$4
    nop
