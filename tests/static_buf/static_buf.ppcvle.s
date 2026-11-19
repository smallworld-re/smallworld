    .text
# Fake the PLT
foobar:
    trap
test:
    # Set up the stack
    e_stwu  1,-112(1)   # Save sp and grow the stack by 112 bytes
    se_mflr 0           # Move link register to r0
    e_stw   0,116(1)    # Store r0 to sp + 116
    e_stw   31,108(1)   # Store bp to sp + 108
    se_mr   31,1        # Move sp to bp

    # int *ret = foobar();
    e_bl    foobar

    # return *ret;
    e_lwz   3,0(3)

    # Clean up the stack
    e_addi  1,31,112    # Restore SP and shrink the stack by 112 bytes
    e_lwz   0,4(1)      # Load link register from sp + 4 to r0
    se_mtlr 0           # move r0 to lr
    e_lwz   31,-4(1)    # Load bp from sp - 4
