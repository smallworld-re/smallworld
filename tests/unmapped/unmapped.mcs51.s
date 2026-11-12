    ; 8051 stand-in for unmapped.elf.c: SDCC writes no ELF, so the harness
    ; enters each routine at a fixed offset (0, 5 and 10; see the unmapped
    ; scenario).  Each touches address 0x8000 in the space it names, which the
    ; harness leaves unmapped.
    .area CSEG (CODE)
read_unmapped:              ; offset 0
    mov     dptr, #0x8000
    movx    a, @dptr        ; XDATA 0x8000
    ret
write_unmapped:             ; offset 5
    mov     dptr, #0x8000
    movx    @dptr, a
    ret
fetch_unmapped:             ; offset 10
    ljmp    0x8000          ; CODE 0x8000
