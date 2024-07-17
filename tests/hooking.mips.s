    .text
    .set noreorder
    .set nomacro
# Fake the PLT.
# gas doesn't have the nice pseudo-ops to assign symbols like nasm has,
# but this will work similarly.
#
# gets is at offset 0x4
# puts is at offset 0x8
gets:
    break
puts:
    break
test:
    # Read an input string into a stack buffer, and write it back out.
    # This requires a stack, and libc models for gets and puts

    # Set up the stack
    addiu   $sp,$sp,-32
    sw      $ra,28($sp)
    sw      $fp,24($sp)
    move    $fp,$sp

    # alloca a 64-byte stack buffer
    addiu   $sp,$sp,-64
    # Put a pointer to the stack buffer in arg1
    move    $a0,$sp
    # Read a string from stdin
    bal     gets
    nop
    # Write the string back to stdout
    bal     puts
    nop
    # Clean up the stack
    addiu   $sp,$sp,64
    move    $sp,$fp
    lw      $ra,28($sp)
    lw      $fp,24($sp)
    addiu   $sp,$sp,32 
