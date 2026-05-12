    .text
test:
    movh    %d2, 20481
    addi    %d2, %d2, 16384
    mov.a   %a2, %d2
    st.w    [%a2]0, %d4
    lea     %a2, [%a2] 4
    st.w    [%a2]0, %d5
    lea     %a2, [%a2] 4
    ld.w    %d2, [%a2]0
