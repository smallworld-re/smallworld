BITS 64;
; DMA example modelling a hardware divisor unit:
; - Write 64-bit numerator to 0x50014000
; - Write 64-bit denominator to 0x50014008
; - Read 64-bit quotient from 0x50014010

divide:
        mov     rdx, 0x50014000
        mov     QWORD [rdx], rdi
        mov     QWORD [rdx + 0x8], rsi
        mov     rax, QWORD [rdx + 0x10]
