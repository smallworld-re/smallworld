    .text
test:
    mov     %d2, 0
.Lloop:
    ld.b    %d3, [%a4]0
    jz      %d3, .Ldone
    lea     %a4, [%a4] 1
    add     %d2, 1
    j       .Lloop
.Ldone:
