    .text
test:
    movhi   hi(0x50014000), r0, r11
    movea   lo(0x50014000), r11, r11
    st.w    r6, 0[r11]      # MMIO[0] = first argument
    st.w    r7, 4[r11]      # MMIO[4] = second argument
    ld.w    8[r11], r10     # result = MMIO[8]
