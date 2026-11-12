    ; Square DPTR into DPTR, modulo 0x10000.
    ;
    ; With DPTR = H:L, (256H + L)^2 = 65536H^2 + 512HL + L^2, so modulo
    ; 0x10000 the square is L*L plus twice the low byte of L*H, shifted
    ; into the high byte.  MUL AB leaves its 16-bit product in B:A.
    .area CSEG (CODE)
_start:
    mov     a, dpl
    mov     b, dpl
    mul     ab              ; B:A = L*L
    mov     r6, a
    mov     r7, b
    mov     a, dpl
    mov     b, dph
    mul     ab              ; A = low byte of L*H
    add     a, acc          ; doubled
    add     a, r7
    mov     dph, a
    mov     dpl, r6
    nop
