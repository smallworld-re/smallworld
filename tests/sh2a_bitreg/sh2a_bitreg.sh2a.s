    .text
    ! SH-2A's register-form bit manipulation: bset, bclr, bld, bst.
    !
    ! Split out from sh2a_diff because `bclr #imm3,Rn` is wrong in the sleigh that
    ! pypcode 3.3.3 and Styx bundle, and keeping it in the differential blob would
    ! knock two of four backends out of a comparison meant to span them.
    !
    ! The bug, for the record.  Ghidra 12.1.2's superh.sinc has:
    !
    !     rn_04_07 = rn_04_07 & (~(1 << imm3_00_02));
    !
    ! while pypcode 3.3.3 and Styx ship an older revision of the same rule:
    !
    !     local b = *:1 (rn_04_07);
    !     *:1 (rn_04_07) = b & (~(1 << imm3_00_02));
    !
    ! i.e. it treats Rn as a *pointer*, clearing a bit in the byte at that address
    ! and leaving the register untouched.  That is the `bclr.b @(disp,Rn)` memory
    ! semantics wrongly applied to the register form.  It is the only difference
    ! between the two files.  Worse than a fault: on both affected backends the
    ! spurious access succeeds - angr's memory is lazily symbolic, Styx maps a flat
    ! 4 GiB - so it corrupts memory at Rn's value and silently returns the wrong
    ! register.
    !
    ! Ghidra 12.1.2 is correct; clearing bit 5 of 0x22 must give 0x02.
sh2a_bitreg:
    mov     #0, r1
    bset    #5, r1              ! r1 = 0x20
    bset    #1, r1              ! r1 = 0x22
    bclr    #5, r1              ! r1 = 0x02   <- the instruction under test
    bld     #1, r1              ! T = bit1 = 1
    movt    r2                  ! r2 = 1
    ! bst's set path: T=1 deposited into a cleared register.
    mov     #0, r3
    bst     #7, r3              ! bit7 = T -> r3 = 0x80

    nott                        ! T = 0

    ! bst's clear path, deliberately on a *different* register whose target bit
    ! is already set.  The obvious form - storing T=0 back into r3's bit7, which
    ! the bst above had just set - cancels, and r3 == 0 is then also satisfied by
    ! bst doing nothing at all, because r3 was zeroed a moment earlier.  Writing
    ! into 0xffffffff instead means a bst that no-ops leaves 0xffffffff, which
    ! the expectation rejects.
    mov     #-1, r5             ! r5 = 0xffffffff
    bst     #7, r5              ! bit7 = T -> r5 = 0xffffff7f

    ! r4 is seeded 0xffffffff by the harness for the same reason: r4 reads 0 at
    ! reset on every backend here, so an unseeded `r4 == 0` would also hold if
    ! movt never executed.
    movt    r4                  ! r4 = 0
    nop
