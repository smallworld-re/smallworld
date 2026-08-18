    .text
    ! MOVML.L / MOVMU.L with Rm = R15, where transfer slot 15 holds PR rather
    ! than R15.
    !
    ! This is a regression test.  An earlier revision of the QEMU SH-2A patch
    ! substituted PR only in MOVMU's last slot and used R15 for MOVML's, so
    ! `movml.l r15,@-r15` silently pushed the stack pointer where the return
    ! address belonged and never restored PR.  gcc -m2a emits the MOVMU form in
    ! essentially every prologue and epilogue, so a backend that gets this wrong
    ! breaks all compiled SH-2A code - and it was caught by review rather than by
    ! a test, which is why this file exists.
    !
    ! The rule, from Ghidra's superh.sinc (storeRegister pre-decrements,
    ! loadRegister post-increments, and index 15 names PR in both instructions
    ! and both directions - so R15 is never itself an operand):
    !
    !   MOVML.L Rm,@-R15   saves R0..Rm             (PR when m == 15)
    !   MOVMU.L Rm,@-R15   saves Rm..R14 and PR     (PR alone when m == 15)
    !
    ! Observations go to scratch memory rather than staying in registers: the
    ! pops restore R0..R14 and would otherwise overwrite them.
sh2a_movml:
    ! Scratch base, below sp and below the deepest push (16 words = 64 bytes).
    mov     r15, r14
    add     #-124, r14

    ! --- MOVML.L with Rm = R15: pushes R0..R14 *and* PR ---
    mov     #0x55, r1
    lds     r1, pr
    movml.l r15, @-r15
    mov     #0x11, r2
    lds     r2, pr                  ! clobber PR while it is saved
    movml.l @r15+, r15
    sts     pr, r1                  ! 0x55 only if slot 15 really is PR
    mov.l   r1, @r14

    ! --- MOVMU.L with Rm = R15: pushes PR alone, a single word ---
    mov     #0x66, r1
    lds     r1, pr
    movmu.l r15, @-r15
    mov     #0x22, r2
    lds     r2, pr
    movmu.l @r15+, r15
    sts     pr, r1                  ! 0x66
    mov.l   r1, @(4, r14)

    ! --- MOVML.L with Rm = R13: R0..R13, so neither R14 nor PR ---
    ! Proves the PR substitution is specific to index 15 rather than applying to
    ! every MOVML: PR was never saved here, so it must come back *clobbered*.
    ! (0x78 rather than 0x88 because `mov #imm,Rn` sign-extends.)
    mov     #0x77, r1
    lds     r1, pr
    movml.l r13, @-r15
    mov     #0x78, r2
    lds     r2, pr
    movml.l @r15+, r13
    sts     pr, r1                  ! 0x78, not 0x77
    mov.l   r1, @(8, r14)

    ! Collect the three observations into distinct registers to check.
    mov.l   @r14, r0
    mov.l   @(4, r14), r3
    mov.l   @(8, r14), r5
