BITS 64;
; This function returns 1 if arg1 is 100 and 0 otherwise
    xor     eax, eax
    cmp     rdi, 100
    sete    al
    nop
