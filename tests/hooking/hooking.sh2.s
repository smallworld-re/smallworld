    .text
! Fake the PLT.
! gas doesn't have the nice pseudo-ops to assign symbols like nasm has,
! but this will work similarly.
!
! SuperH instructions are two bytes wide, so - like m68k - the two stub slots
! sit two bytes apart rather than the four the default spec assumes:
!   gets is at offset 0x0
!   puts is at offset 0x2
! The harness replaces both with models, so these bodies never execute; they
! only have to be real two-byte instructions that fail loudly if they do.
gets:
    trapa   #0
puts:
    trapa   #1
test:
    ! Read an input string into a stack buffer, and write it back out.
    ! This requires a stack, and libc models for gets and puts.

    ! alloca a 64-byte stack buffer
    add     #-64, r15

    ! Materialise the address of the fake PLT (the blob is loaded at 0x1000).
    ! SH-2A's movi20 is not available, and a PC-relative literal pool would land
    ! after the last instruction, where the harness's exit point sits, so build
    ! the constants from 8-bit immediates instead.
    mov     #0x10, r1
    shll8   r1                  ! r1 = 0x1000 = &gets
    mov     r1, r2
    add     #2, r2              ! r2 = 0x1002 = &puts

    ! Put a pointer to the stack buffer in arg1, then read a string from stdin.
    mov     r15, r4
    jsr     @r1
    nop                         ! delay slot: runs before the call is taken

    ! Write the string back to stdout.
    mov     r15, r4
    jsr     @r2
    nop                         ! delay slot: runs before the call is taken

    ! Clean up the stack
    add     #64, r15
    nop
