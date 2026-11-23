    .arch armv4t
    .text
test:
    # ARMv4T has no blx, so switching state takes an adr and a bx. To keep
    # the Thumb block at 0x10, the ARM block adds 2 in one instruction where
    # the ARMv5T version uses two; the totals are the same.
    mov r1, #1
    add r0, r0, #2
    adr r2, thumb + 1
    bx r2

    .thumb
thumb:
    movs r1, #1
    adds r0, r1
    adds r0, #1
    adr r2, arm
    bx r2

    .arm
    # Keep the ARM block at offset 0x20, where the test expects it.
    .balign 16
arm:
    mov r1, #1
    add r0, r1
    add r0, #1
    nop
