BITS 64;
; amd64 uses fsbase and gsbase which are MSRs in order to determine
; address meant by fs:[0x28]  
mov rax, fs:[0x28]
mov rbx, gs:[0x13]
	
