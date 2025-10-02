    .text
_start:
    bl      main
mc91:
    # Set up the stack frame
    push    {fp, lr}
    add     fp, sp, #4
    sub     sp, sp, #8

    # Check if we want case 1 or case 2
    cmp     r0, #100
    ble     .L2

    # Case 1: n > 100 -> M(n) := n - 10
    sub     r0, r0, #10
    b       .L3
.L2:
    # Case 2: n <= 100 -> M(n) := M(M(n + 11))
    add     r0, r0, #11
    bl      mc91
    bl      mc91
.L3:
    # Clean up stack and return
    sub     sp, fp, #4
    pop     {fp, pc}
main:
    bl      mc91 
    nop
