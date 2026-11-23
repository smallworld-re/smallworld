    .code16
    .text
_start:
    jmp     main
mc91:
    # Set up the stack frame
    push    %bp
    mov     %sp, %bp

    # Load arg1
    mov     4(%bp), %ax

    # Check if we want case 1 or case 2
    cmp     $100, %ax
    jle     .L2

    # Case 1: n > 100 -> M(n) := n - 10
    sub     $10, %ax
    jmp     .L3

.L2:
    # Case 2: n > = 100 -> M(n) := M(M(n + 11))
    add     $11, %ax
    push    %ax
    call    mc91
    add     $2, %sp
    push    %ax
    call    mc91
    add     $2, %sp

.L3:
    # Clean up stack and return
    pop     %bp
    ret

main:
    # Remove the old return address, so we return here.
    pop     %ax
    call    mc91
