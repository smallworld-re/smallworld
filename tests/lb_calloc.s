BITS 64;
; instruction just before these gets a random value in rax
; so that's to be an input of the harness
;	
;	00409a47 e8 1c 8f        CALL       <EXTERNAL>::rand                                 int rand(void) 
;                 ff ff

MOV        EDX, 0x92492493
MOV        R12D, EAX
MOV        EDI, 0xe
IMUL       EDX
MOV        EAX, R12D
MOV        rsi, 0x1
SAR        EAX, 0x1f
ADD        EDX, R12D
SAR        EDX, 0x3
SUB        EDX, EAX
IMUL       EDX, EDI
SUB        R12D, EDX
LEA        EDI, [R12 + 0x3]
MOVSXD     RDI, EDI

;
; instruction immediately following all this is a calloc that's using rdi, rsi as its 2 args
;
; 00409a7c e8 e7 8d        CALL       <EXTERNAL>::calloc                               void * calloc(size_t __nmemb, size)
;
; So the "output" of this that's of interest is values in rdi & rsi.
