    .text
test:
    ! Jump to a null pointer.  jmp takes a delay slot, so the nop after it
    ! executes before the branch is taken.
    mov     #0, r3
    jmp     @r3
    nop
    nop
