    .text
test:
    mov r1, #1
    add r0, r1
    add r0, #1
    blx thumb

    .thumb
thumb:
    # Plain 16-bit Thumb: ARMv5T and ARMv6K have no Thumb-2, so the
    # non-flag-setting `mov`/`add` forms of these aren't encodable.
    movs r1, #1
    adds r0, r1
    adds r0, #1
    blx arm

    .arm
    # Keep the ARM block at offset 0x20, where the test expects it.
    .balign 16
arm:
    mov r1, #1
    add r0, r1
    add r0, #1
    nop
