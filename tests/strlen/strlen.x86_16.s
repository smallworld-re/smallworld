# Real-mode addressing can't index off dx, so the string pointer is in si.
    .code16
    .text
strlen:
    push    %bp
    mov     %sp, %bp

    mov     4(%bp),%si
    mov     $0x0, %ax

.L3:
    cmpb    $0x0,(%si)
    je      .L4
    add     $0x1,%si
    add     $0x1,%ax
    jmp     .L3

.L4:
    pop     %bp
