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

    ! Materialise the address of the fake PLT (the blob is loaded at 0x1000)
    ! with shifts rather than a PC-relative literal pool: a pool would land
    ! after the last instruction, where the harness's exit point sits, and
    ! would be executed as code.
    mov     #0x10, r1
    shll8   r1                  ! r1 = 0x00001000 = &gets
    mov     r1, r2
    add     #2, r2              ! r2 = 0x00001002 = &puts

    ! Put a pointer to the stack buffer in arg1, then read a string from stdin.
    !
    ! The call is `jsr @Rn`, not the shorter `bsr`, and that is deliberate.
    ! Models return by writing Model.get_return_address, which on SuperH reads
    ! `pr`.  Ghidra's SuperH4.sinc `:bsr` never assigns PR at all, so under angr
    ! and pcode `bsr` leaves pr untouched: measured, pcode returns to pc=0x0 and
    ! faults, and angr raises SymbolicValueError because pr is unconstrained.
    ! Its `:jsr` does assign `PR = inst_next`, and sleigh's inst_next counts the
    ! delay slot as part of the instruction, so pr lands on the architectural
    ! inst_start+4 - measured identical (0x101e for the jsr at 0x101a) on
    ! angr, pcode and panda.  `bsrf` is likewise correct; only `bsr` is broken.
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
