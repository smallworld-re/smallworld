; fake the PLT
gets@PLT equ 0x2800
puts@PLT equ 0x2808

BITS 64;
; This program reads an input string and then writes it out again using libc.
; This requires external calls, notionally to gets and puts which will need to
; be modeled.
        mov     rbp, rsp
        sub     rsp, 64
        mov     rdi, rsp
        call    gets@PLT
        call    puts@PLT
        nop
