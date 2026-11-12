    ; 8051 stand-in for exitpoint.elf.c: SDCC writes no ELF, so this is a raw
    ; blob whose `main` starts at offset 0 and runs to the end.
    ;
    ; The harness runs main twice: with an exit point at the fake return
    ; address it pushes, which `ret` lands on, and with one at main's last
    ; instruction (main + sizeof(main) - 1).  Both runs must leave 42 in DPTR.
    .area CSEG (CODE)
main:
    mov     dptr, #42
    ret
