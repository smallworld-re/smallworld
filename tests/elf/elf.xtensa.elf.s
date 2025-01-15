    .text
    .literal_position
    .align  4
    .globl  _start
    .type   _start, @function
_start:
    # Load argc
    l32i    a2, sp, 0
    
    # If argc != 2, exit
    bnei    a2, 2, .L2

    # Load argv
    l32i    a3, sp, 4
    # Load argv[1]
    l32i    a3, a3, 4

    movi    a2, 0

.L3:
    # for(i = 0; argv[1][i] != '\0'; i++);
    add     a4, a2, a3
    l8ui    a4, a4, 0
    beqz    a4, .L1
    addi    a2, a2, 1
    j       .L3 
    
.L2: 
    # Failed; return 1
    movi    a2, 1

.L1:
    # Leave, by any means necessary
    ret

