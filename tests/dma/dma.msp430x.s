    .text
divide:
    mov #0x5000, r13
    mov r15, 0(r13)
    mov r14, 2(r13)
    mov 4(r13), r15
    
