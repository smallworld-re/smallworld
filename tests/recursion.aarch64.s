    .text
mc91:
    # Set up the stack frame
    stp     x29, x30, [sp, -32]!
    mov     x29, sp

    # Test if we want case 1 or case 2
    cmp     w0, 100
    ble     .L2

    # Case 1: n > 100 -> M(n) := n - 10
    sub     w0, w0, #10
    b       .L3
.L2:
    # Case 2: n <= 100 -> M(n) := M(M(n + 11))
    add     w0, w0, 11
    bl      mc91
    bl      mc91
.L3:
    # Clean up the stack and return
    ldp     x29, x30, [sp], 32
    ret 
