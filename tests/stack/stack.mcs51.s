    ; Sum the first and third register arguments (r7 and r5) and the argument
    ; on top of the stack into the accumulator.
    .area CSEG (CODE)
manyargs:
    mov     r0, sp          ; SP through its SFR address
    mov     a, @r0
    add     a, r7
    add     a, r5
    nop
