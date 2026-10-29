    .text
manyargs:
    # Take nine args, add 1, 3, 5, 7, 9.
    # se_add only reaches r0-r7 and r24-r31, so r9 and r10 use the
    # 32-bit add, which VLE keeps from the standard encoding.
    se_add  3,5
    se_add  3,7
    add     3,3,9
    e_lwz   10,24(1)
    add     3,3,10
