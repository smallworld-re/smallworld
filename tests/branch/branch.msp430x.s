    .text
_start:
    cmp #100, r15
    jne .L2
    mov #1, r14
    jmp .L3

.L2:
    mov #0, r14

.L3:
    nop
