    .text
# Fake the PLT
foobar:
    trap
test:
    # Set up the stack
    stwu    1,-112(1)   # Save sp and grow the stack by 112 bytes
    mflr    0           # Move link register to r0
    stw     0,116(1)    # Store r0 to sp + 116
    stw     31,108(1)   # Store bp to sp + 108
    mr      31,1        # Move sp to bp

    # int *ret = foobar();
    bl      foobar

    # return *ret;
    lwz     3,0(3)

    # Clean up the stack
    addi    1,31,112    # Restore SP and shrink the stack by 112 bytes
    lwz     0,4(1)      # Load link register from sp + 4 to r0
    mtlr    0,          # move r0 to lr
    lwz     31,-4(1)    # Load bp from sp - 4  
    
