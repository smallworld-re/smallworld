    ; Fake the PLT: the harness hooks gets at offset 0 and puts at offset 1.
    ; The buffer is 64 bytes of internal RAM at 0x80, passed in r0; the
    ; 8051's internal RAM is too small to carve it out of the stack.
    .area CSEG (CODE)
gets:
    nop
puts:
    nop
test:
    mov     r0, #0x80
    lcall   gets
    mov     r0, #0x80
    lcall   puts
    nop
