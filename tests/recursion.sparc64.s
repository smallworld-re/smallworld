    .text
mc91:
    # Set up the stack frame.
    save    %sp, -176, %sp

    # Check if we want case 1 or case 2
    cmp     %i0, 100
    ble,pn  %icc, .L4
    nop

    # Case 1: n > 100 -> M(n) := n - 10
    add     %i0, -10, %i0
    b       .L5
    nop
.L4:
    # Case 2: n <= 100 -> M(n) := M(M(n + 11)
    add     %i0, 11, %i0
    call    mc91, 0
    sra     %i0, 0, %o0
    call    mc91, 0
    nop
    sra     %o0, 0, %i0
.L5:
    # Clean up the stack and return
    return %i7 + 8
