BITS 64;
; Mccarthy 91, a simple recursive function
_start:
        jmp     main
mc91:
        xchg    edi, eax
        cmp     eax, 100
        jle     .L10
        sub     eax, 10
        ret
.L10:
        push    rdx
.L9:
        lea     edi, [rax+11]
        call    mc91
        cmp     eax, 100
        jle     .L9
        sub     eax, 10
        pop     rcx
        ret
main:
        call    mc91
