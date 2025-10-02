BITS 64;
_start:
        call    main
strlen:
        cmp     BYTE [rdi], 0
        je      .L4
        mov     edx, 1
.L3:
        mov     rax, rdx
        add     rdx, 1
        cmp     BYTE [rdi-1+rdx], 0
        jne     .L3
        ret
.L4:
        mov     eax, 0
        ret
main:
        call    strlen
    nop
