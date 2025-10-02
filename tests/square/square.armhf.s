    .text
square:
    # Square the first argument (r0)
    # and save it to the return (r0)
    # The assembler complains if I do this in one op
    mov r1, r0
    mul r0, r1, r0
    nop
