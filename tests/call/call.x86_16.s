# Real-mode addressing can't index off sp, so arguments are read through bp.
    .code16
    .text
_start:
    call    foo
bar:
    push    %bp
    mov     %sp,%bp

    mov     4(%bp),%dx
    mov     %dx,%ax
    shl     $3,%ax
    cmp     $101,%dx
    jl      .L1
    mov     $32,%ax
.L1:
    pop     %bp
    ret
foo:
    push    %bp
    mov     %sp,%bp

    mov     4(%bp),%ax
    sub     $1,%ax
    push    %ax
    call    bar
    add     $1,%ax

    add     $2,%sp
    pop     %bp
