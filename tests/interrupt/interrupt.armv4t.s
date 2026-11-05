    .text
_start:
    # ARMv4 and ARMv4T have no bkpt (ARMv5 added it), so trap with swi.
    swi 0
