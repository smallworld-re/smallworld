    .text
# Taint-propagation exercise for the Triton backend; see taint.amd64.s for the
# data-flow the harness checks. 32-bit registers and 4-byte scratch slots here.
taint:
    mov     $0x3000, %ebx
    mov     %edi, %eax
    add     $1, %eax
    mov     %eax, (%ebx)
    mov     (%ebx), %ecx
    mov     %esi, 4(%ebx)
    mov     4(%ebx), %edx
    mov     8(%ebx), %ebp
    mov     $0, %edi
