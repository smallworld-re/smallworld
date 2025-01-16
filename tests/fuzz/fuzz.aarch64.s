    .text
vuln:
    ldr     w1, [x0]
    cmp     w1, 11
    bls     .L3
    ldrb    w1, [x0, 4]
    cmp     w1, 98
    beq     .L2
.L1:
    mov     x0, 0
    b       .L4
.L2:
    ldrb    w1, [x0, 5]
    cmp     w1, 97
    bne     .L1
    ldrb    w1, [x0, 6]
    cmp     w1, 100
    bne     .L1
    ldrb    w1, [x0, 7]
    cmp     w1, 33
    bne     .L1
    ldrb    w1, [x0, 8]
    mov     x2, 0x5678
    movk    x2, 0x1234, lsl 16
    str     x1, [x2]  
.L3:
    mov     x0, xzr
.L4:
    nop
    
 
