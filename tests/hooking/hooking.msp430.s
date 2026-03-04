# Fake the PLT.
# gas doesn't have the nice pseudo-ops to assign symbols like nasm has,
# but this will work similarly
# gets is at offset 0x0
# puts is at offset 0x2
gets:
    nop
puts:
    nop
test:
    # Set up the stack
    push    r4
    mov     r1, r4
    add     #2, r4
    sub     #2, r1

    # Alloca a 64-byte stack buffer
    sub     #64, r1
    
	# Put a pointer to the stack buffer in arg1
    mov     r4, r15
    sub     #66, r15

    # Read a string from stdin
    call    gets
    
    # Put the pointer back into arg1
    mov     r4, r15
    sub     #66, r15

    # Write the string to stdout
    call    puts

    # restore the stack
    add     #66, r1
    pop     r4

    # fake return
    nop
    
    
