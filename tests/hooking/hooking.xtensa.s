    .text
# Fake the PLT.
# gas doesn't have the nice pseudo-ops to assign symbols like nasm has,
# but this will work similarly.
#
# gets is at offset 0x4
# puts is at offset 0x8
gets:
    ill.n
    ill.n
puts:
    ill.n
    ill.n
test:
    # Read an input string into a stack buffer, and write it back out.
    # This requires a stack, and libc models for gets and puts

    # alloca a 64-byte stack buffer
    addi    $sp, $sp, -64 
    # Put a pointer to the stack buffer in arg1
    mov     $a2, $sp
    # Read a string from stdin
    call0   gets
    # Write the string back to stdout
    call0   puts
    nop
