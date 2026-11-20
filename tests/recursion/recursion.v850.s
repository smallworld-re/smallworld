    .text
mc91:
    movea   101, r0, r11
    cmp     r11, r6
    blt     .Lrecurse
    addi    -10, r6, r10
    jmp     [lp]
.Lrecurse:
    # jarl overwrites lp, so keep the caller's on the stack.
    add     -4, sp
    st.w    lp, 0[sp]
    addi    11, r6, r6
    jarl    mc91, lp
    mov     r10, r6
    jarl    mc91, lp
    ld.w    0[sp], lp
    add     4, sp
    jmp     [lp]
main:
    jarl    mc91, lp
