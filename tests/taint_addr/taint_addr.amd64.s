BITS 64;
; Address-taint exercise: load through a tainted base pointer and a tainted
; index register. The loaded memory is itself untainted, so any taint on the
; destination comes purely from the address computation.
;
; Inputs (set + labeled by the harness):
;   rdi = base pointer         (labeled "ptr")
;   rbx = base pointer         (unlabeled)
;   rcx = index                (labeled "idx")
; The buffer bytes at [rdi] and [rbx+rcx] are left unlabeled.
        mov     rax, [rdi]          ; rax <- *ptr           (base-register address)
        mov     rdx, [rbx + rcx]    ; rdx <- *(base + idx)  (index-register address)
