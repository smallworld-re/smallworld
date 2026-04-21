    .text
_start:
    j       main

mc91:
    mov.aa  %a14, %SP
    sub.a   %SP, 8
    st.w    [%a14] -4, %d4
    ld.w    %d2, [%a14] -4
    lt      %d2, %d2, 101
    jnz     %d2, .Lrecurse
    ld.w    %d2, [%a14] -4
    addi    %d2, %d2, -10
    mov.aa  %SP, %a14
    ret     #mc91
.Lrecurse:
    ld.w    %d2, [%a14] -4
    addi    %d2, %d2, 11
    mov     %d4, %d2
    call    mc91
    mov     %d4, %d2
    call    mc91
    mov.aa  %SP, %a14
    ret     #mc91

main:
    call    mc91
