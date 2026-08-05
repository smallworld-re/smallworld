BITS 64;
; Dynamic taint-tracking exercise.
;
; Inputs (set by the harness):
;   rdi = taint source "a"
;   rsi = taint source "b"
;   rdx = pointer to an 8-byte scratch buffer (taint source "ptr")
;   r8  = taint source "clearme"
;
; Exercises: register->register copy, arithmetic taint union, register->memory
; store, memory->register load, and a taint-clearing idiom.
        mov     rax, rdi        ; rax <- a
        add     rax, rsi        ; rax <- a | b
        mov     [rdx], rax      ; store a | b to the buffer
        mov     rcx, [rdx]      ; load it back into rcx
        xor     r8, r8          ; clears r8's taint
