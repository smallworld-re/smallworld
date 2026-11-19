    .text
# Fake the PLT.
# gas doesn't have the nice pseudo-ops to assign symbols like nasm has,
# but this will work similarly.
#
# gets is at offset 0x0
# puts is at offset 0x4
gets:
    break 0
puts:
    break 1
test:
    # Read an input string into a stack buffer,
    # and write it back out.
    # This requires a stack, and libc models for gets and puts
    
    # Set up the stack
    addi.w  $sp,$sp,-48
    st.w    $ra,$sp,40
    st.w    $fp,$sp,32
    addi.w  $fp,$sp,48

    # alloca a 64-byte stack buffer
    addi.w  $sp,$sp,-64
    # Put a pointer to the stack buffer in arg1
    move    $a0,$sp
    # Read a string from stdin
    bl      gets
    # Write the string right back to stdout
    bl      puts

    # Clean up the stack
    addi.w  $sp,$sp,64
    ld.w    $fp,$sp,32
    ld.w    $ra,$sp,40
    addi.w  $sp,$sp,48
