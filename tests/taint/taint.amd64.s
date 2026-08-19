BITS 64;
; Taint-propagation exercise for the Triton backend.
;
; The harness marks some subset of the inputs as tainted, runs this, and then
; asks Triton which registers and scratch slots came out tainted. Every step is
; a plain data movement so the expected taint is exactly the data-flow graph:
;
;   rdi -> rax -> [scratch+0] -> rcx     (tainted when rdi is tainted)
;   rsi -> [scratch+8] -> rdx            (tainted when rsi is tainted)
;   [scratch+16] -> r8                   (tainted when that slot is tainted)
;
; rdi is finally overwritten with a constant, which must clear its taint.
        mov     rbx, 0x3000
        mov     rax, rdi
        add     rax, 1
        mov     [rbx], rax
        mov     rcx, [rbx]
        mov     [rbx+8], rsi
        mov     rdx, [rbx+8]
        mov     r8, [rbx+16]
        mov     rdi, 0
