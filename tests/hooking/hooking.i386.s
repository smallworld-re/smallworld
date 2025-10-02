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
    push    %ebp
    mov     %esp,%ebp

    # Alloca a 64-byte stack buffer
    sub     $64,%esp
    # Put a pointer to the buffer in arg1
    push    %esp
    # Read a string from stdin
    call    gets
    # Write the string back to stdout
    call    puts
    
    # Clean up the stack
    add     $68,%esp
    pop     %ebp
    nop
