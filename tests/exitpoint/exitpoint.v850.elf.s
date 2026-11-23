    .text
    .globl _start
    .globl main
    .type _start, @function
    .type main, @function
_start:
main:
    movea   42, r0, r10
    jmp     [lp]
    .size main, .-main
    .size _start, .-_start
