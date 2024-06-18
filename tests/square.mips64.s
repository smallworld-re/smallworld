    .text
square:
    # Square the first argument ($4)
    # and save the lower 32 bits of the result
    # to the return register ($2)
    mult $4,$4
    mflo $2
