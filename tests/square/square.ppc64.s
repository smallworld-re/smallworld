    .section	".text"
    .machine power7
square:
    # Square the first integer argument (3)
    # and sign-extend it into the return register (3)
    mullw 3,3,3
    extsw 3,3
    nop
