    .text
test:
    mov     r6, r10
    # mul writes the 64-bit product's low word to its second register and
    # its high word to its third; r0 discards the high word.
    mul     r6, r10, r0
