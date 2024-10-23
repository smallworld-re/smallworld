    .machine    ppc
    .align      2
    .globl      _start
    .type       _start, @function
_start:
    # Load argc
    lwz         4,0(1)
    
    # If argc != 2, exit
    cmpwi       0,4,2
    bne         0,.L2

    # Load argv
    lwz         4,4(1)
    # Load argv[1]
    lwz         4,4(4)

    li          3,0

.L3:
    # for(i = 0; argv[1][i] != '\0'; i++);
    add         5,4,3
    lbz         5,0(5)
    cmpwi       0,5,0
    beq         0,.L1
    addi        3,3,1
    b           .L3

.L2:
    # Failure; return -1
    li          3,-1

.L1:
    blr 
    
    .size       _start, .-_start
