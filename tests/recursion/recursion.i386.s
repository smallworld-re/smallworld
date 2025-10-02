    .text
_start:
    jmp     main
mc91:
    # Set up the stack frame
    push    %ebp
    mov     %esp, %ebp
    
    # Load arg1
    mov     0x8(%ebp), %eax
    
    # Check if we want case 1 or case 2
    cmp     $100, %eax
    jle     .L2

    # Case 1: n > 100 -> M(n) := n - 10
    sub     $10, %eax
    jmp     .L3

.L2:
    # Case 2: n > = 100 -> M(n) := M(M(n + 11))
    add     $11, %eax
    push    %eax
    call    mc91
    add     $4, %esp
    push    %eax
    call    mc91
    add     $4, %esp

.L3:
    # Clean up stack and return
    pop     %ebp
    ret

main:
    # Remove the old return address, so we return here.
    pop     %eax
    call    mc91
    nop
