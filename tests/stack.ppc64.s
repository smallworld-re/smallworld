    .text
manyargs:
    # Take nine args, add 1, 3, 5, 7, 9.
    # Return sign-extended int result.
    # I didn't make the stack offset; I just work here.
    lwa 10,116(1)
    add 3,3,5
    add 3,3,7
    add 3,3,9
    add 3,3,10
    extsw 3,3
