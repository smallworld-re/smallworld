    .text
test:
    mov     %d2, 0
    eq      %d3, %d4, 100
    jz      %d3, .Ldone
    mov     %d2, 1
.Ldone:
