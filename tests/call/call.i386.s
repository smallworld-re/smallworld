    .text
_start:
    call    foo
bar:
    push    %ebp
    mov     %esp,%ebp
    
    mov     0x8(%esp),%edx
    lea     (,%edx,8),%eax
    cmp     $101,%edx
    mov     $32,%edx
    cmovge  %edx,%eax

    pop     %ebp
    ret
foo:
    push    %ebp
    mov     %esp,%ebp 

    mov     0x8(%ebp),%eax
    sub     $1,%eax
    push    %eax
    call    bar
    add     $1,%eax

    add     $4,%esp
    pop     %ebp
    nop
