; fake the PLT
foobar@PLT equ 0x2800

BITS 64;
    call    foobar@PLT
    mov     DWORD eax,[rax]
    nop
