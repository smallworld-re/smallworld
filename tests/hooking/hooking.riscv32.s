    .text
# Fake the PLT.
# gas doesn't have the nice pseudo-ops to assign symbols like nasm has,
# but this will work similarly.
#
# gets is at offset 0x0
# puts is at offset 0x2
gets:
    ebreak
puts:
    ebreak
test:
    # Read an input string into a stack buffer, and write it back out.
    # This requires a stack, and libc models for gets and puts

    # Set up the stack
    addi    t0, sp, -4
    sw      ra, 0x0(sp)

    # alloca a 64-byte stack buffer
    addi    sp, sp, -64
    # Put a pointer to the stack buffer in arg1
    mv      a0, sp
    # Read a string from stdin
    jal     ra, gets 
    # Write the string back to stdout
    jal     ra, puts

    # Clean up the stack
    addi    sp, sp, 64
    lw      ra, 0x0(sp)
    addi    sp, sp, 4
