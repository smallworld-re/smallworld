    ; DPTR = (DPTR == 100)
    .area CSEG (CODE)
_start:
    mov     a, dph
    jnz     .L2
    mov     a, dpl
    cjne    a, #100, .L2
    mov     dptr, #1
    sjmp    .L3
.L2:
    mov     dptr, #0
.L3:
    nop
