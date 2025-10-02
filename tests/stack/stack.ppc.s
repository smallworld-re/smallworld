    .text
manyargs:
    # Take nine args, add 1, 3, 5, 7, 9.
    add 3,3,5
    add 3,3,7
    add 3,3,9
    lwz 10,24(1)
    add 3,3,10
    nop
