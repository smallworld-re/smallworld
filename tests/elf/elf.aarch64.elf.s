    .text
    .globl _start
    .type _start, @function
_start:
    # Load argc
    ldr     w2, [sp]

    # If argc != 2, leave.
    cmp     w2, 2
    bne     .L2

    # Load argv
    ldr     x1, [sp,8]
    # Load argv[1]
    ldr     x1, [x1,8]
    
    mov     x0, 0
.L3:
    # for(i = 0; argv[1][i] != '\0'; i++);
    add     x2,x1,x0
    ldrb    w2,[x2]

    cmp     w2, 0
    beq     .L1
    add     x0, x0, 1
    b       .L3
    
.L2:
    # Failure; return -1
    mov     x0, -1
.L1:
    # Leave, by any means necessary
    ret
    .size _start, .-_start
