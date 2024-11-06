BITS 64;
        jmp     .L2
.L3:
        mov     eax, edi 
        mov     edx, eax
        sar     edx, 31
        idiv    esi
        mov     ebx, eax
        mov     eax, edi
        mov     edx, eax
        sar     edx, 31
        idiv    esi
        mov     ecx, edx
        mov     eax, esi
        mov     edi, eax
        mov     eax, ecx
        mov     esi, eax
.L2:
        cmp     esi, 0
        setg    al
        test    al, al
        jne     .L3
        mov     eax, edi
