    .text
test:
    ! Tests single-stepping and hooking of delay-slot instructions.
    ! If the branches are not taken correctly, the return value is wrong.
    !
    ! Only `bra` is used for the delayed branches.  SuperH's conditional delayed
    ! branches, `bt/s` and `bf/s`, are ambiguous across our backends: Ghidra's
    ! sleigh executes their delay slot unconditionally, while the Renesas
    ! pseudocode reads as skipping it when the branch is not taken.  Plain `bt`
    ! has no delay slot at all, so pairing it with `bra` for the delayed
    ! branches keeps this test's expectations identical on every emulator.
    !
    ! No SR preamble is needed even though the T bit is only a field of SR on
    ! SH-2A: `tst` writes T immediately before `bt` reads it, and both operands
    ! are concrete, so T is never read while undefined.

    ! Loop flag
    mov     #1, r1

    ! An address to dereference.  Built with a shift rather than a PC-relative
    ! literal pool: a literal would sit past the last instruction, where the
    ! harness's exit point makes the loader treat it as code.
    mov     #0x20, r2
    shll8   r2

    mov     #1, r0

    bra     .L1
    mov.l   r0, @r2         ! delay slot: writes 1

    ! Dead block - the branch above must skip it
    mov     #-1, r0
    mov.l   r0, @r2

.L1:
    add     #1, r0
    tst     r1, r1          ! T = 1 only once r1 has been cleared
    bt      .L2             ! no delay slot
    mov.l   r0, @r2         ! only reached while falling through

    bra     .L1
    mov     #0, r1          ! delay slot: clears the loop flag

    ! Dead block - the branch above must skip it
    mov     #-1, r0

.L2:
    add     #1, r0
    mov.l   r0, @r2
