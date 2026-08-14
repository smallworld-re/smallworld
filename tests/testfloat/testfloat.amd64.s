BITS 64
; Berkeley TestFloat kernels for x86-64, SSE scalar.
;
; Four loops, one per (precision, arity), each at a fixed offset so the harness
; can pick an entry point without parsing the binary.  The arithmetic
; instruction of each loop is patched in by the harness: the SSE scalar forms
; addss/subss/mulss/divss share the encoding F3 0F xx C1 and differ only in the
; opcode byte (58/5C/59/5E), and the double forms are the same table under the
; F2 prefix - so four loops cover every operation instead of needing one blob
; per operation.
;
; Contract (identical on every architecture):
;   rdi = input base, rsi = output base, rdx = case count (> 0)
;   inputs are packed operands, little-endian, no padding
;   each iteration writes one result to the output cursor
;   every loop leaves via the shared `done` label at offset 0x100
;
; Unlike the SuperH kernels there is no control-register prologue.  SuperH has
; to install FPSCR itself because its reset rounding mode is round-to-zero,
; whereas the MXCSR bits TestFloat cares about - RC (round-to-nearest-even) and
; the FTZ/DAZ denormal switches - are all zero at reset.  Measured by running a
; `stmxcsr` blob on each backend: unicorn 0x0000, angr 0x1F80, pcode 0x0000.
; They disagree only about the exception *mask* bits (0x1F80 is the
; architectural reset value, all six masked), which this scenario does not
; compare, so nothing needs seeding.  If a backend ever starts with FTZ or DAZ
; set, hand MXCSR in through `setup` and add an `ldmxcsr` prologue here -
; remembering that it moves every patch offset.
;
; Instruction lengths matter here in a way they do not on a fixed-width ISA: the
; harness overwrites exactly len(patch) bytes at patch_offset, so the patched
; instruction and every replacement must be the same length and land on a real
; instruction boundary.  The register-direct forms used below are 4 bytes each;
; the operand loads deliberately keep the operands in xmm0/xmm1 so the patch's
; ModRM byte (C1 = xmm0, xmm1) is the same for both precisions.

    ; ------------------------------------------------------------------
    ; 0x00: f32 binary - two f32 operands in, one f32 out.
    ; ------------------------------------------------------------------
f32_binary:
.loop:
    movss   xmm0, [rdi]             ; operand a
    movss   xmm1, [rdi+4]           ; operand b
    add     rdi, 8
    addss   xmm0, xmm1              ; PATCHED: addss/subss/mulss/divss
    movss   [rsi], xmm0
    add     rsi, 4
    dec     rdx
    jnz     .loop
    jmp     done

    ; `times` rather than `align`: a loop that outgrew its 0x40 slot has to be
    ; a build error, not silently shifted padding.
    times   0x40-($-$$) db 0x90

    ; ------------------------------------------------------------------
    ; 0x40: f32 unary - one f32 operand in, one f32 out.
    ; ------------------------------------------------------------------
f32_unary:
.loop:
    movss   xmm0, [rdi]
    add     rdi, 4
    sqrtss  xmm0, xmm0              ; PATCHED: sqrtss
    movss   [rsi], xmm0
    add     rsi, 4
    dec     rdx
    jnz     .loop
    jmp     done

    times   0x80-($-$$) db 0x90

    ; ------------------------------------------------------------------
    ; 0x80: f64 binary - two f64 operands in, one f64 out.
    ; ------------------------------------------------------------------
f64_binary:
.loop:
    movsd   xmm0, [rdi]
    movsd   xmm1, [rdi+8]
    add     rdi, 16
    addsd   xmm0, xmm1              ; PATCHED: addsd/subsd/mulsd/divsd
    movsd   [rsi], xmm0
    add     rsi, 8
    dec     rdx
    jnz     .loop
    jmp     done

    times   0xC0-($-$$) db 0x90

    ; ------------------------------------------------------------------
    ; 0xC0: f64 unary - one f64 operand in, one f64 out.
    ; ------------------------------------------------------------------
f64_unary:
.loop:
    movsd   xmm0, [rdi]
    add     rdi, 8
    sqrtsd  xmm0, xmm0              ; PATCHED: sqrtsd
    movsd   [rsi], xmm0
    add     rsi, 8
    dec     rdx
    jnz     .loop
    jmp     done

    times   0x100-($-$$) db 0x90

    ; ------------------------------------------------------------------
    ; 0x100: shared exit.  The harness sets its only exit point here.
    ; ------------------------------------------------------------------
done:
    nop
