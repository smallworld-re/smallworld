    .text
multiargs:
    lw t0,0(sp)
    add  a0,a0,a2
    add  a0,a0,a4
    add  a0,a0,a6
    add  a0,a0,t0 
    nop
