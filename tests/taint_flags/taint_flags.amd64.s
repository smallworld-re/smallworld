BITS 64;
; Demonstrates a documented limitation of concrete taint tracking: flows that
; pass through the condition flags are not tracked, because propagation is
; driven by each instruction's explicit register/memory operands and the flags
; register is not one of them.
;
; Inputs (set + labeled by the harness):
;   rdi = "a"   rsi = "b"   (distinct, so the comparison is not equal)
;   rax = 0     (unlabeled)
;
; `al` ends up depending on rdi and rsi *through the flags*, but a concrete
; taint run leaves it untainted.
        cmp     rdi, rsi        ; flags <- (a ?= b)   (flags are not tracked)
        sete    al              ; al <- ZF            (reads only the flags)
