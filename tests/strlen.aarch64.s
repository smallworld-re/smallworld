    .text
_start:
    bl      main
strlen:
    # Zero out the counter register
    mov     w1, wzr
.L0:
    # Get the first character in arg1
    ldrb    w2, [x0]
    # If the character is NULL, return
    cmp     w2, 0
    beq     .L1
    # Increment the counter,
    # and set arg1 = arg1[1:]
    add     w1,w1,1
    add     x0,x0,1
    # Try again
    b       .L0
.L1:
    # Return the counter
    mov     w0, w1
    ret
main:
    bl      strlen
