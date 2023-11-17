BITS 64;
; basic function call
bar:
        lea     eax, [0+rdi*8]
        cmp     edi, 101
        mov     edx, 32
        cmovge  eax, edx
        ret
foo:
        sub     edi, 1
        call    bar
        add     eax, 1
