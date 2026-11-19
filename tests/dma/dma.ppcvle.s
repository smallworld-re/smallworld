    .text
divide:
    e_lis   5,0x5001
    e_add16i 5,5,0x4000
    e_stw   3,0(5)
    e_stw   4,4(5)
    e_lwz   3,8(5)
