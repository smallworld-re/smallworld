    .syntax unified
    .thumb
    .text
test:
    movs r7, #4
    svc #0x0
    nop
