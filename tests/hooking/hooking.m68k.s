    .text
# Fake the PLT
# gas doesn't have the nice pseudo-ops to assign symbols like nasm has,
# but this will work similarly.
#
# gets is at offset 0x0
# puts is at offset 0x2
gets:
    trap #0
puts:
    trap #1
test:
    # Read an input string into a stack buffer, and write it back out.
    # This requires a stack, and libc models for gets and puts.

    # Set up the stack,
    # including alloca'ing a 64-byte stack buffer
    link.l    %fp,#-64
    
    # Put a pointer to the stack buffer in arg1
    mov.l   %sp,-(%sp)
    # Read a string from stdin
    jsr     gets
    # Write the string back to stdou
    jsr     puts
    # Clean up the stack
    unlk %fp
    nop
    
