    .text
divide:
    li.d    $t0,0x50014000
    st.d    $a0,$t0,0
    st.d    $a1,$t0,8
    ld.d    $a0,$t0,16
