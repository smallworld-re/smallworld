    .text
multiargs:
    # Take nine args,
    # add 1, 3, 5, 7, 9,
    # return result
    # This includes two more args,
    # since aarch64 can fit eight arguments in its registers.
    ldr w1, [sp]
    add w0, w0, w2
    add w0, w0, w4
    add w0, w0, w6
    add w0, w0, w1
