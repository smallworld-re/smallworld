    .text
    .globl _start
    .type _start, @function
_start:
    ld.w    %d2, [%SP]0
    eq      %d2, %d2, 2
    jz      %d2, .Lfail
    ld.a    %a2, [%SP] 4
    ld.a    %a2, [%a2] 4
    mov     %d2, 0
.Lloop:
    ld.b    %d3, [%a2]0
    jz      %d3, .Ldone
    lea     %a2, [%a2] 1
    add     %d2, 1
    j       .Lloop
.Lfail:
    mov     %d2, -1
.Ldone:
    ji      %a11
    .size _start, .-_start
