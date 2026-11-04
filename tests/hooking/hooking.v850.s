    .text
gets:
    .long   0
puts:
    .long   0
test:
    addi    -64, sp, sp
    mov     sp, r6
    jarl    gets, lp
    mov     sp, r6
    jarl    puts, lp
    addi    64, sp, sp
