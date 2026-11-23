    ; basic function call, on 16-bit values in DPTR:
    ; foo(x) = bar(x - 1) + 1, bar(x) = x >= 101 (signed) ? 32 : x * 8.
    ; Like the other per-arch versions, foo never returns: it runs off the end
    ; of the blob into the harness exit point.
    .area CSEG (CODE)
_start:
    ; Put PSW into a known state before anything reads the carry.  A symbolic
    ; backend would otherwise start it unconstrained, and `clr c` alone leaves
    ; the rest of PSW symbolic.
    mov     psw, #0
    lcall   foo
bar:
    ; Signed compare against 101: flip both sign bits, then compare unsigned.
    clr     c
    mov     a, dpl
    subb    a, #101
    mov     a, dph
    xrl     a, #0x80
    subb    a, #0x80
    jc      .Lshift
    mov     dptr, #32
    ret
.Lshift:
    mov     r7, #3
.Lloop:
    mov     a, dpl          ; DPTR <<= 1
    add     a, acc
    mov     dpl, a
    mov     a, dph
    rlc     a
    mov     dph, a
    djnz    r7, .Lloop
    ret
foo:
    clr     c               ; DPTR -= 1
    mov     a, dpl
    subb    a, #1
    mov     dpl, a
    mov     a, dph
    subb    a, #0
    mov     dph, a
    lcall   bar
    inc     dptr
