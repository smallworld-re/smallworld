    .text
    .globl      _start
    .type       _start, @function
_start:
    # Load argc
    e_lwz       4,0(1)

    # If argc != 2, exit
    e_cmpi      0,4,2
    e_bne       0,.L2

    # Load argv
    e_lwz       4,4(1)
    # Load argv[1]
    e_lwz       4,4(4)

    se_li       3,0

.L3:
    # for(i = 0; argv[1][i] != '\0'; i++);
    # VLE has no 16-bit three-operand add; the standard 32-bit one remains.
    add         5,4,3
    e_lbz       5,0(5)
    e_cmpi      0,5,0
    e_beq       0,.L1
    se_addi     3,1
    se_b        .L3

.L2:
    # Failure; return -1
    e_li        3,-1

.L1:
    se_blr

    .size       _start, .-_start
