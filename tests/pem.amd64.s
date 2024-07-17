BITS 64;
;typedef struct pkey {
;    uint8_t     version;
;    size_t      modulus_len;
;    size_t      pub_exp_len;
;    size_t      priv_exp_len;
;    size_t      prime_1_len;
;    size_t      prime_2_len;
;    size_t      exp_1_len;
;    size_t      exp_2_len;
;    size_t      coeff_len;
;    uint8_t     modulus[512];
;    uint8_t     pub_exp[512];
;    uint8_t     priv_exp[512];
;    uint8_t     prime_1[512];
;    uint8_t     prime_2[512];
;    uint8_t     exp_1[512];
;    uint8_t     exp_2[512];
;    uint8_t     coeff[512];
;};
global  parse_int
parse_int:
    ; Parse a DER-encoded integer
    ; 
    ; rdi:      Pointer to data buffer      (uint8_t **)
    ; rsi:      Pointer to buffer length    (size_t *)
    ; rdx:      Pointer to field length     (uint64_t *)
    ; rcx:      Pointer to field            (uint8_t *; assumed to be length 512)
    ; return:   0 on success
    ; return:   1 on failure
    push    rbx             ; Store rbx; I need it.
    mov     rax, 0x0        ; Zero out rax;
    mov     rbx, 0x0        ; Zero out rbx;
    mov     r8, QWORD [rdi] ; Store address of data buffer in r8.
    mov     r9, QWORD [rsi] ; Store size of data buffer in r9
; Sanity-check the buffer length
    cmp     r9, 0x2         ; Compare the buffer length to 2.
    jl      .FAIL           ; We need at _least_ two bytes to do our job
; Test the type field
    mov     al, BYTE [r8]   ; Load the type byte from the buffer
    cmp     al, 0x02        ; Compare the type byte to 2.
    jne     .FAIL           ; If it's not 2, fail
    add     r8, 0x1         ; Shift r8 to buf+1
    sub     r9, 0x1         ; Decrement buffer length appropriately
; Figure out if the length is short-form or long-form
    mov     al, BYTE [r8]   ; Load the first byte of the length
    and     al, 0x80        ; AND the first byte of the length with 0x80
    cmp     al, 0x0         ; Check if the top-most bit is set
    jne     .LONG           ; The bit is set; this is a long-form length
.SHORT:
; Length is a single byte, encoded in buf[1]
    mov     al, BYTE [r8]   ; Load the length from the first byte.
    add     r8, 0x1         ; Shift r8 to buf+2
    sub     r9, 0x1         ; Decrement buffer length appropriately
    jmp     .LOAD
.LONG:
; Length is multiple bytes, encoded in buf[2:2 + (buf[1] & ~0x80)]
; Load the length from the buffer
    mov     rax, 0x0        ; Clear rax; it will store the length
    mov     bl, BYTE [r8]   ; Load the length's length from the first byte into
    and     bl, 0x7f        ; Clear the upper flag bit
    add     r8, 0x1         ; Shift r8 to buf[2], the start of the length field.
    sub     r9, 0x1         ; Decrement buffer length appropriately
; Check the length for sanity
    cmp     rbx, 0x8        ; Check if the length's length is greater than 8 bytes
    jg      .FAIL           ; If it is, it won't fit in size_t
    cmp     rbx, rsi        ; Compare the length's length against the buffer length
    jg      .FAIL           ; If the length's length is longer than our buffer, fail.
.LONG_LOOP:
; Rebuild the big-endian integer from memory
    cmp     rbx, 0x0        ; Check if we are out of bytes
    je      .LOAD           ; If we are, go to done
    shl     rax, 0x8        ; Shift RAX one byte up
    mov     r10b, BYTE [r8] ; Load the next byte of length
    add     rax, r10        ; Add the current byte to the length
    add     r8, 0x1         ; Shift r8 one byte to the left
    sub     r9, 0x1         ; Decrement the buffer length appropriately
    sub     rbx, 0x1        ; Decrement the length length
    jmp     .LONG_LOOP      ; Loop again    
.LOAD:
; We have the field length; load the data
; Check if we have enough buffer left
    cmp     rax, r9         ; Check if field length is greater than buffer length
    jg      .FAIL           ; We don't have enough bytes.  Fail.
; Check if we have enough field buffer
    cmp     rax, 0x200      ; Check if field length is greater than 512
    jg      .FAIL           ; We don't have enough bytes.  Fail.
; We're good.  Let's actually load
    mov     QWORD[rdx], rax ; Store the field length in the field length
    sub     r9, rax         ; Subtract the field length from the buffer length
.LOAD_LOOP:
    cmp     rax, 0x0        ; Check if we've run out of bytes
    je      .SUCCESS        ; We're done!  Yay!
    mov     bl, BYTE [r8]   ; Load the next byte into bl
    mov     BYTE [rcx], bl  ; Store the next byte into the field buffer
    add     r8, 0x1         ; Shift the data buffer one byte
    add     rcx, 0x1        ; Shift the field buffer one byte
    sub     rax, 0x1        ; Decrement the number of bytes remaining
    jmp     .LOAD_LOOP      ; Keep going
.SUCCESS:
    mov     QWORD [rdi], r8 ; Store the new data buffer position in *rdi
    mov     QWORD [rsi], r9 ; Store the new data buffer length in *rsi
    mov     rax, 0x0        ; Set return to Success
    pop     rbx             ; restore rbx
    ret
.FAIL:
    mov     rax, 0x1        ; Set return to Fail
    pop     rbx             ; restore rbx
    ret
    
    

parse:
    ; rdi:      Pointer to output struct
    ; rsi:      Pointer to data buffer
    ; rdx:      Length of data buffer
    ; return:   0 on success
    ; return:   1 on failure
