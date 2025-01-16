    .text
    .globl _start
    .type _start, @function
_start:
    # Load argc
    ld      t0, 0x0(sp)
    
    # If argc != 2, leave
    li      t1, 2
    bne     t0, t1, .L2

    # Load argv
    ld      t0, 0x8(sp)
    # Load argv[1]
    ld      t0, 0x8(t0)
    
    li      a0, 0
.L3:
    # for(i = 0; argv[1][i] != '\0'; i++);
    add     t1, t0, a0
    lb      t1, 0x0(t1)
    beq     t1, zero, .L1
    addi    a0, a0, 1
    j       .L3

.L2:
    # Failure; return -1
    li      a0, -1

.L1:
    # Leave, by any means necessary
    ret
    .size _start, .-_start
