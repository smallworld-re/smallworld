BITS 64;
; This is my attempt to emulate a DMAish setup. It continues to read from an address until that address is nonzero and then masks it and returns it.

function:
        mov     rdx, 4702394921427289928
.L2:
        mov     eax, DWORD [rdx]
        test    eax, eax
        jne     .L2
        and     eax, -559038737
