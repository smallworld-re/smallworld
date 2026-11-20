    ; The harness hooks foobar with a model that writes 0x000004A1 (big-endian)
    ; to a buffer in XDATA and returns its address in DPTR.  Read the low 16
    ; bits back into DPTR.
    .area CSEG (CODE)
foobar:
    nop                     ; placeholder for the model; test is at offset 1
test:
    lcall   foobar
    inc     dptr            ; skip the high 16 bits
    inc     dptr
    movx    a, @dptr
    mov     r6, a
    inc     dptr
    movx    a, @dptr
    mov     dpl, a
    mov     dph, r6
    nop
