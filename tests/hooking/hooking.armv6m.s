    .text
    .syntax unified
    # M-profile CPUs run only Thumb. This sticks to the Thumb-1 subset, so the
    # same code runs on ARMv6-M.
    .thumb
# Fake the PLT.
# gas doesn't have the nice pseudo-ops to assign symbols like nasm has,
# but this will work similarly.
#
# gets is at offset 0x0
# puts is at offset 0x2
    .thumb_func
gets:
    bkpt
    .thumb_func
puts:
    bkpt
    .thumb_func
test:
    # Read an input string into a stack buffer, and write it back out.
    # This requires a stack, and libc models for gets and puts

    # Set up the stack
    push {r7, lr}
    # alloca a 64-byte stack buffer
    sub sp, sp, #64
    # Put a pointer to the stack buffer in arg1
    mov r0, sp
    # Read a string from stdin
    bl gets
    # Write the string back to stdout
    bl puts
    # Clean up the stack (Thumb-1 can't pop into lr directly)
    add sp, sp, #64
    pop {r7}
    pop {r1}
    mov lr, r1
