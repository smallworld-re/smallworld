_start:
    link.w  %fp,#0

    move.l  8(%fp),%d0
    move.l  %d0,-(%sp)
    jsr     main
    addq.l  #4, %sp

    unlk    %fp


mc91:
    # Set up the stack frame
    link.w  %fp,#0

    # Check if we want case 1 or case 2
    move.l  8(%fp),%d0
    cmpi.l  #100, %d0
    ble     .L2

    # Case 1: n > 100 -> M(n) := n - 10
    subi.l  #10, %d0
    bra     .L3

.L2:
    # Case 2: n <= 100 -> M(n) := M(M(n + 11))
    addi.l  #11, %d0

    move.l  %d0,-(%sp)
    jsr     mc91
    addq.l  #4, %sp

    move.l  %d0,-(%sp)
    jsr     mc91
    addq.l  #4, %sp

.L3:

    # Clean up the stack and return
    unlk    %fp
    rts

main:
    link.w  %fp,#0

    move.l  8(%fp),%d0
    move.l  %d0,-(%sp)
    jsr     mc91
    nop
