    .text
_start:
    # ARMv4 and ARMv4T have no bkpt (ARMv5 added it), so trap with an
    # instruction that is permanently undefined on every ARM.
    .word 0xe7f000f0
