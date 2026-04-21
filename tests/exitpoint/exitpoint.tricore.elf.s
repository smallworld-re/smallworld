    .text
    .globl _start
    .globl main
    .type _start, @function
    .type main, @function
_start:
main:
    mov     %d2, 42
    ji      %a11
    .size main, .-main
    .size _start, .-_start
