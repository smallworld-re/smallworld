    .text
    ! SH-2A's 32-bit memory forms and its bit-manipulation-on-memory set.
    !
    ! These are the instructions SH-2A adds that touch memory, and they are the
    ! bulk of the twenty-four 32-bit encodings - the only 32-bit instructions
    ! anywhere in the SuperH family.  None of them exists on SH-1..SH-4, so
    ! assembling this file with --isa=sh4a fails outright.
    !
    ! Two things here are easy for a backend to get wrong and are checked
    ! explicitly: the zero- versus sign-extending loads (movu.w against mov.w on
    ! the same stored halfword), and the displacement scaling, which differs per
    ! width - unscaled for .b, by 2 for .w, by 4 for .l.
    !
    ! Scratch memory sits 128 bytes below the incoming stack pointer.  That is
    ! deliberately clear of the 64 bytes a movml.l push would use, so this blob
    ! and sh2a_isa_call can share a stack layout.
sh2a_isa_mem:
    mov     r15, r13
    add     #-128, r13          ! r13 = scratch base

    ! *** Displaced 32-bit halfword access, and extension semantics ***
    ! 0x1234 is positive, so movu.w and mov.w agree on it.
    movi20  #0x1234, r1
    mov.w   r1, @(4, r13)
    movu.w  @(4, r13), r2       ! r2 = 0x00001234
    mov.w   @(4, r13), r3       ! r3 = 0x00001234

    ! 0x8000 has its top bit set, so the two loads must now differ.  A backend
    ! that implements movu.w as a sign-extending load returns 0xffff8000 in r5.
    movi20  #0x8000, r4
    mov.w   r4, @(8, r13)
    movu.w  @(8, r13), r5       ! r5 = 0x00008000  (zero-extended)
    mov.w   @(8, r13), r6       ! r6 = 0xffff8000  (sign-extended)

    ! *** Displaced 32-bit longword access ***
    movi20  #0x5a5a5, r7
    mov.l   r7, @(16, r13)
    mov.l   @(16, r13), r8      ! r8 = 0x0005a5a5

    ! *** All ten bit operations on @(disp12,Rn) ***
    ! One byte walked through every form.  The T-bit results are sampled into
    ! r10/r11/r12 at three points, and the final byte is read back into r14, so
    ! both halves of each instruction's effect are observable.
    mov     #0, r0
    mov.b   r0, @(40, r13)      ! byte = 0x00
    bset.b  #3, @(40, r13)      ! byte = 0x08
    bset.b  #0, @(40, r13)      ! byte = 0x09
    bclr.b  #3, @(40, r13)      ! byte = 0x01
    bld.b   #0, @(40, r13)      ! T = bit0        = 1
    movt    r10                 ! r10 = 1
    bst.b   #4, @(40, r13)      ! bit4 = T        -> byte = 0x11
    band.b  #0, @(40, r13)      ! T = T & bit0    = 1 & 1 = 1
    bor.b   #1, @(40, r13)      ! T = T | bit1    = 1 | 0 = 1
    bxor.b  #0, @(40, r13)      ! T = T ^ bit0    = 1 ^ 1 = 0
    movt    r11                 ! r11 = 0
    bldnot.b  #1, @(40, r13)    ! T = ~bit1       = 1
    bandnot.b #0, @(40, r13)    ! T = T & ~bit0   = 1 & 0 = 0
    bornot.b  #1, @(40, r13)    ! T = T | ~bit1   = 0 | 1 = 1
    movt    r12                 ! r12 = 1
    movu.b  @(40, r13), r14     ! r14 = 0x11, the byte the ten ops left behind

    ! *** mov.b R0,@Rn+ and mov.b @-Rm,R0 ***
    ! SH-2A-only addressing modes, and the only ones with their data operand
    ! fixed to R0.  Storing then reloading through the same pointer leaves it
    ! where it started, so r9 is also an assertion about the two side effects
    ! cancelling.
    !
    ! Placed last on purpose: the destination of `mov.b @-Rm,R0` is fixed at R0,
    ! so this has to be the final writer of R0 or the bit-op section above would
    ! overwrite the result being checked.
    mov     r13, r9
    add     #32, r9             ! r9 = scratch + 32
    mov     #0x7b, r0           ! 123
    mov.b   r0, @r9+            ! [scratch+32] = 0x7b, then r9 += 1
    mov     #0, r0              ! prove the reload really happens
    mov.b   @-r9, r0            ! r9 -= 1, then r0 = 0x0000007b
    nop
