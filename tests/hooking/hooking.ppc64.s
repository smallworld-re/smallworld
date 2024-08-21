    .text
# Fake the PLT
# gas doesn't have the nice pseudo-ops to assign symbols like nasm has,
# but this will work similarly.
#
# gets is at offset 0x4
# puts is at offset 0x8
gets:
    trap
puts:
    trap
test:
    # Read an input string into a stack buffer, and write it back out.
    # This requires a stack, and libc models for gets and puts.

    # Set up the stack
    mflr    0
    std     0,16(1)
    std     31,-8(1)
    stdu    1,-224(1)
    mr      31,1

    addi    3,31,136
    bl      gets

    addi    3,31,136
    bl      puts

    addi    1,31,224
    ld      0,16(1)
    mtlr    0
    ld      31,-8(1)
    blr

