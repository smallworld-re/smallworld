BITS 64;
; Comprehensive taint-propagation exercise, checked after a single emulation.
;
; Inputs (set + labeled by the harness):
;   rdi="a" rsi="b" rdx="c" r10="d" r9="e" r12="f" r14="g"
;   rbx = pointer to scratch buffer (unlabeled)
;   r13 = untainted value (unlabeled)
;
; Covers: register copy, arithmetic union, three-source accumulation,
; register->memory->register round trip, taint clearing via xor and sub,
; clearing via overwrite from an untainted source, byte-granular propagation,
; and (via r13) absence of spurious taint.
        mov     rax, rdi        ; rax <- a                (copy)
        add     rax, rsi        ; rax <- a | b            (arithmetic union)
        mov     [rbx], rax      ; store a | b             (reg -> mem)
        mov     rcx, [rbx]      ; rcx <- a | b            (mem -> reg)
        xor     rdx, rdx        ; rdx cleared             (xor r,r idiom)
        mov     r8, r10         ; r8 <- d
        sub     r8, r8          ; r8 cleared              (sub r,r idiom)
        mov     r9, r13         ; r9 <- untainted         (overwrite clears "e")
        mov     r15, rdi        ; r15 <- a
        add     r15, rsi        ; r15 <- a | b
        add     r15, r12        ; r15 <- a | b | f        (three sources)
        mov     r14b, sil       ; r14 low byte <- b       (byte-granular; keeps "g")
