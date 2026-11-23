    ; Jump to a null pointer.  Code is loaded at 0x1000, so address 0 is
    ; unmapped.
    .area CSEG (CODE)
test:
    mov     dptr, #0
    clr     a
    jmp     @a+dptr
    nop
