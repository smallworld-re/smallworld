    .text
square:
    # Square the first argument (a0)
    # and sign-extend the result to the return (a0)
    mulw  a0,a0,a0
    nop
