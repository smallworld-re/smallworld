BITS 64; 

vuln:
        cmp     DWORD [rdi], 11
        jbe     .L5
        cmp     BYTE [rdi+4], 98
        je      .L7
.L3:
        xor     eax, eax
        jmp     .FAKERET
.L7:
        cmp     BYTE [rdi+5], 97
        jne     .L3
        cmp     BYTE [rdi+6], 100
        jne     .L3
        cmp     BYTE [rdi+7], 33
        jne     .L3
        movsx   rax, BYTE [rdi+8]
        mov     QWORD ds:305419896, rax
        jmp     .L3
.L5:
        mov     eax, -1
.FAKERET:
        nop
