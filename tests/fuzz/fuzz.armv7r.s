    .text
vuln:
    ldr     r1, [r0]
    cmp     r1, #11
    bls     .L3
    ldrb    r1, [r0, #4]
    cmp     r1, #98
    beq     .L2
.L1:
    mov     r0, #0
    b       .L4
.L2:
    ldrb    r1, [r0, #5]
    cmp     r1, #97
    bne     .L1
    ldrb    r1, [r0, #6]
    cmp     r1, #100
    bne     .L1
    ldrb    r1, [r0, #7]
    cmp     r1, #33
    bne     .L1
    ldrb    r1, [r0, #8]
    mov     r2, #0x5678
    mov     r3, #0x1234
    orr     r2, r2, r3, lsl #16
    str     r1, [r2]
.L3:
    mov     r0, #-1
.L4:
    nop 
