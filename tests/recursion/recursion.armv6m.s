    .syntax unified
    .thumb
    .text
_start:
    bl      main
mc91:
    # Set up the stack frame; r7 is the Thumb frame pointer
    push    {r7, lr}
    add     r7, sp, #0
    sub     sp, #8
    # Check if we want case 1 or case 2
    cmp     r0, #100
    ble     .L2
    # Case 1: n > 100 -> M(n) := n - 10
    subs    r0, r0, #10
    b       .L3
.L2:
    # Case 2: n <= 100 -> M(n) := M(M(n + 11))
    adds    r0, r0, #11
    bl      mc91
    bl      mc91
.L3:
    # Clean up stack and return
    mov     sp, r7
    pop     {r7, pc}
main:
    bl      mc91
