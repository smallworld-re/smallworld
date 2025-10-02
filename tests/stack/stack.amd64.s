BITS 64;
; This function takes 7 64-bit arguments and returns the sum of the 1st (rdi), 3rd (rdx), 5th(r8), and 7th([rsp+8].
; 
        add     rdi, rdx
        lea     rax, [rdi+r8]
        add     rax, QWORD [rsp+8]
    nop
