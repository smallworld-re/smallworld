    .text
! Fake the PLT; the harness models these.
!
! gets is at offset 0x0
! puts is at offset 0x4
gets:
    unimp   0
puts:
    unimp   0
test:
    ! Read an input string into a stack buffer, and write it back out.
    ! This requires a stack, and libc models for gets and puts.

    ! Open a register window with a frame that holds a 64-byte buffer
    ! above the 96-byte minimum frame.
    save    %sp, -160, %sp
    ! Read a string from stdin into the buffer
    call    gets
     add    %sp, 96, %o0
    ! Write the string back to stdout
    call    puts
     add    %sp, 96, %o0
    ! Close the window; running off the end of the code ends the test
    restore
