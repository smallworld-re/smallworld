    .text
_start:
    call    foo

bar:
    # r13 = r15 * 8
    # No multiply or shift-left-by-amount instruction.
    # Hang onto your hats.
    mov     #0, r12
    mov     r15, r13
.L2:
    rla     r13
    add     #1, r12
    cmp     #8, r12
    jl      .L2

    # if(r15 < 101)

foo:
