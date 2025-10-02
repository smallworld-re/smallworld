BITS 64;
test_syscall:
; %edi:     (int)       file descriptor
; %rsi:     (void *)    buffer
; %rdx:     (size_t)    cap
; return:   (ssize_t)   # written, or -1 for error
	mov     eax, 0x1
	syscall
    nop
    nop
