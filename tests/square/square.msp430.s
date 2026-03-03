    .text
_start:
    # Multiply r15 by r15
    # msp430 has no integer multiply instruction.
    # This is about to get messy

    # r15 is x
    # r14 is out
    # r12 is i

    # i = 0;
    # out = 0;
    mov     #0, r12
    mov     #0, r14

    # do {
.L2:
    #   out += x;
    #   i += 1
    add     r15, r14
    add     #1, r12
    

    # } while(i < x); 
    cmp     r15, r12
    jl      .L2

    nop
