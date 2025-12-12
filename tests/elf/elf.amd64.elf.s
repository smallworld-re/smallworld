    .text
    .globl _start
    .type _start, @function
_start:
    # Load argc
    mov     0x8(%rsp),%rdi

    # If argc != 2, leave.
    cmp     $2,%rdi
    jne     .L2

    # Load argv
    mov     0x10(%rsp),%rdi
    # Load argv[1]
    mov     0x8(%rdi),%rdi

    
    mov     $0,%rax
.L3:
    # for(i = 0; argv[1][i] != '\0'; i++);
    cmpb    $0,(%rdi,%rax)
    je      .L1
    add     $1,%rax
    jmp     .L3
    
.L2:
    # Failure; return -1
    mov     $-1,%rax
.L1:
    # Leave, by any means necessary
    ret
    .size _start, .-_start
