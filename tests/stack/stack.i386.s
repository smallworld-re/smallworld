    .text
multi_arg:
    push %ebp
    mov  %esp, %ebp
    # i386 only passes args on the stack.
    # 0x00: Saved frame pointer
    # 0x04: Return address
    # 0x08: arg1
    # ...    
    
    # ret = arg1 ...
    mov 0x8(%ebp), %eax
    # ... + arg 3
    mov 0x10(%ebp), %ecx
    add %ecx, %eax
    # ... + arg5
    mov 0x18(%ebp), %ecx
    add %ecx, %eax
    # ... + arg7
    mov 0x20(%ebp), %ecx
    add %ecx, %eax

    pop %ebp
