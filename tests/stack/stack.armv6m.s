    .syntax unified
    .thumb
    .text
manyargs:
    # Take seven args,
    # add 1, 3, 5, 7
    # return the sum
    # armv6m only uses four registers for arguments,
    # so we get two stack-passed values
    ldr r1, [sp]
    ldr r3, [sp, #8]
    adds r0, r0, r2
    adds r0, r0, r1
    adds r0, r0, r3
