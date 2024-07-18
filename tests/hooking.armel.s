    .text
# Fake the PLT.
# gas doesn't have the nice pseudo-ops to assign symbols like nasm has,
# but this will work similarly.
#
# gets is at offset 0x4
# puts is at offset 0x8
gets:
    bkpt
puts:
    bkpt
test:
    # Read an input string into a stack buffer, and write it back out.
    # This requires a stack, and libc models for gets and puts

    # Set up the stack
    push {fp, lr}
    # alloca a 64-byte stack buffer
    sub sp, sp, #64
    # Put a pointer to the stack buffer in arg1
    mov r0, sp
    # Read a string from stdin
    bl gets
    # Write the string back to stdout
    bl puts
    # Clean up the stack
    add sp, sp, #64
    pop {fp, lr}
