    .text
manyargs:
    # Function takes seven arguments
    # Add arguments 1, 3, 5, and 7
    # I got this stack offset from the compiler.
    # Yes, the sparc64 stack is insane
    ld  [%fp + 2227],%l0
    add %i0,%i2,%i0
    add %i0,%i4,%i0
    add %i0,%l0,%i0
