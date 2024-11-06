    .text
strlen:
    save    %sp, -176, %sp
    mov     0, %l0
.L2:
    ldub    [%i0], %l1
    cmp     %l1, 0
    beq     %icc, .L3
    add     %l0, 1, %l0
    add     %i0, 1, %i0
.L3:
    mov     %l0, %i0
    return  %i7 + 8
