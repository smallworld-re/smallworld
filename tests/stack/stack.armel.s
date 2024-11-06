    .text
manyargs:
    # Take seven args,
    # add 1, 3, 5, 7
    # return the sum
    # armel only uses four registers for arguments,
    # so we get two stack-passed values
    ldr r1, [sp]
    ldr r3, [sp, #8]
    add r0, r0, r2
    add r0, r0, r1
    add r0, r0, r3
