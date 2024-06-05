    .text
strlen:
    mov     w1, wzr
.L0:
    ldrb    w2, [x0]
    cmp     w2, 0
    beq     .L1
    add     w1,w1,1
    add     x0,x0,1
    b       .L0
.L1:
    mov     w0, w1
    ret
