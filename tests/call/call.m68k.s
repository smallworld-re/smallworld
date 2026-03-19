    .text
_start:
    jsr     foo
bar:
    movq.l  #8,%d1
    mulu.l  %d0,%d1
    cmpi.l  #101,%d0
    bge     .L2
    mov.l   %d1,%d0
    bra     .L3
.L2:
    movq.l  #32,%d0
.L3:
    rts
foo:
    subi.l  #1,%d0
    jsr     bar
    addi.l  #1,%d0
