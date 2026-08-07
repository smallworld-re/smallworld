    .text
gets:
    .word   0
puts:
    .word   0
test:
    sub.a   %SP, 64
    mov.aa  %a4, %SP
    call    gets
    mov.aa  %a4, %SP
    call    puts
    lea     %SP, [%SP] 64
