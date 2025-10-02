    .text
strlen:
    push    %ebp
    mov     %esp, %ebp

    mov     0x8(%ebp),%edx
    mov     $0x0, %eax
    
.L3:
    cmpb    $0x0,(%edx)
    je      .L4
    add     $0x1,%edx
    add     $0x1,%eax
    jmp     .L3

.L4:
    pop     %ebp
    
