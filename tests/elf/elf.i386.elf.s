    .text
    .globl  _start
    .type   _start, @function
_start:
    # If argc != 2, leave
    cmpl    $2,(%esp)
    jne     .L2

    # Load argv
    mov     0x4(%esp),%ebx
    # Load argv[1]
    mov     0x4(%ebx),%ebx

    mov     $0,%eax
.L3:
    # for(i = 0; argv[1][i] != '\0'; i++);
    cmpb    $0,(%ebx,%eax)
    je      .L1
    add     $1,%eax
    jmp     .L3

.L2:
    # Failure; return -1
    mov     $-1,%eax
.L1:
    ret
    .size   _start, .-_start
