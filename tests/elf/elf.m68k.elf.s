    .text
    .globl  _start
_start:
    # Load argc
    mov.l   4(%sp),%d0
   
    # If argc != 2, exit
    cmpi.l  #2,%d0
    bne     .L2

    # Load argv
    mova.l  8(%sp),%a0
    # Load argv1
    mova.l  4(%a0),%a0
   
    # Set output to zero 
    movq.l  #0,%d0

.L3:
    mov.b   (%a0)+,%d1
    beq     .L1
    addi.l  #1,%d0
    bra     .L3

.L2:
    # Failed; return -1
    movq.l  #-1,%d0

.L1:
    # Return
    rts
