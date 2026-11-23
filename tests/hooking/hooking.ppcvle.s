    .text
# Fake the PLT
# gas doesn't have the nice pseudo-ops to assign symbols like nasm has,
# but this will work similarly.
#
# gets is at offset 0x0
# puts is at offset 0x4
gets:
    trap
puts:
    trap
test:
    # Read an input string into a stack buffer, and write it back out.
    # This requires a stack, and libc models for gets and puts.

    # Set up the stack
    e_stwu  1,-112(1)   # Save sp and grow the stack by 112 bytes
    se_mflr 0           # Move link register to r0
    e_stw   0,116(1)    # Store r0 to sp + 116
    e_stw   31,108(1)   # Store bp to sp + 108
    se_mr   31,1        # Move sp to bp

    # Read a string from stdin
    # into an already-allocated buffer
    e_addi  3,31,28     # Set arg1 to bp + 28
    e_bl    gets

    # Write the string back to stdout
    e_addi  3,31,28
    e_bl    puts

    # Clean up the stack
    e_addi  1,31,112    # Restore SP and shrink the stack by 112 bytes
    e_lwz   0,4(1)      # Load link register from sp + 4 to r0
    se_mtlr 0           # Move r0 to lr
    e_lwz   31,-4(1)    # Load bp from sp - 4
