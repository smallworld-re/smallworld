    .text
multiargs:
    # Take nine args,
    # add 1, 3, 5, 7, 9,
    # return result
    # This includes two more args,
    # since aarch64 can fit eight arguments in its registers.
    # The ninth arg fills the low-order half of an 8-byte stack slot, which
    # is its first word little-endian and its second big-endian, so load the
    # whole slot.
    ldr x1, [sp]
    add w0, w0, w2
    add w0, w0, w4
    add w0, w0, w6
    add w0, w0, w1
