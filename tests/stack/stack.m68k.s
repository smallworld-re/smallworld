    .text
multi_arg:
    # m68k only passes args on the stack
    # 0x00: Return address
    # 0x04: arg1
    # ...

    move.l  4(%sp), %d0
    add.l   12(%sp), %d0
    add.l   20(%sp), %d0
    add.l   28(%sp), %d0
