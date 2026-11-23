    .code16
    .text
# Fake the PLT.
# gas doesn't have the nice pseudo-ops to assign symbols like nasm has,
# but this will work similarly.
gets:
    int3
puts:
    int3
rest:
    # Read an input string into a stack buffer, and write it back out.
    # This requires a stack, and libc models for gets and puts.
    push    %bp
    mov     %sp,%bp

    # Alloca a 64-byte stack buffer
    sub     $64,%sp
    # Put a pointer to the buffer in arg1
    push    %sp
    # Read a string from stdin
    call    gets
    # Write the string back to stdout
    call    puts

    # Clean up the stack
    add     $66,%sp
    pop     %bp
