BITS 64;
; This function takes 7 64-bit arguments and returns the sum of the 1st, 3rd, 5th, and 7th.
; 
        add     rdi, rdx
        lea     rax, [rdi+r8]
        add     rax, QWORD [rsp+8]
