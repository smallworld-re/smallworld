    .text
    .globl _start
    .type _start, @function
_start:
    # Load argc off the stack
    ld.w    $a0,$sp,0

    # If argc != 2, leave
    li.w    $t0,2
    bne     $a0,$t0,.L2

    # Load argv
    ld.d    $t0,$sp,8
    # Load argv[1]
    ld.d    $t0,$t0,8

    li.w    $a0,0
.L3:
    # for (i = 0; i < argv[1][i] != '\0'; i++);
    ld.b    $t1,$t0,0

    beq     $t1,$zero,.L1
    
    addi.d  $t0,$t0,1
    addi.w  $a0,$a0,1

    b       .L3

.L2:
    # Failure; return -1
    li.w    $a0,-1

.L1:
    # Leave, by any means necessary
    ret
    .size _start, .-_start
    
