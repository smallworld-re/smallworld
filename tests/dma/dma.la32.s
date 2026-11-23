    .text
divide:
    li.w    $t0,0x50014000
    st.w    $a0,$t0,0
    st.w    $a1,$t0,4
    ld.w    $a0,$t0,8
