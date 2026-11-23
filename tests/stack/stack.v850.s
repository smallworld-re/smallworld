    .text
manyargs:
    # The fifth word argument is the first on the stack.
    ld.w    0[sp], r10
    add     r6, r10
    add     r8, r10
