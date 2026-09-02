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
    !
    ! Nothing here reads the T bit, so this needs no `ldc ..., sr` preamble.

    ! alloca a 64-byte stack buffer
    add     #-64, r15

    ! Materialise the address of the fake PLT (the blob is loaded at 0x1000).
    ! movi20 is an SH-2A 32-bit form that carries the constant inline, so no
    ! PC-relative literal pool is needed - a pool would land after the last
    ! instruction, where the harness's exit point sits, and be run as code.
    movi20  #0x1000, r1         ! r1 = &gets
    movi20  #0x1002, r2         ! r2 = &puts

    ! Put a pointer to the stack buffer in arg1, then read a string from stdin.
    !
    ! `jsr @Rn` rather than `bsr` keeps this source parallel to the SH-4 one,
    ! where Ghidra's sleigh never writes PR on `bsr`.  SH-2A's own superh.sinc
    ! is fine: pr after bsr/bsrf/jsr was measured architecturally correct on
    ! all four SH-2A engines (angr, pcode, panda, styx), so either form works.
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
