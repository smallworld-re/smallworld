    .text
    ! Exercise instructions that exist only on SH-2A, so a backend claiming
    ! SH-2A support is actually held to it.  Every instruction below is rejected
    ! on SH-4, and the assembler enforces that too: building this file with
    ! --isa=sh4a fails with "opcode not valid for this cpu variant".
    !
    ! Takes no argument and leaves a fixed result in r0, so one comparison
    ! covers every step.  Expected result: 0x36b4f.
sh2a_isa:
    ! Put the status register into a fully known state before anything reads the
    ! T bit.  SH-2A's sleigh model has no standalone T register - T is the
    ! bitfield sr[0,1] - so a symbolic-state backend that starts with sr
    ! unconstrained would otherwise carry that symbol through tst/movt into the
    ! result.  Writing the whole register makes every bit concrete; `clrt` alone
    ! is not enough, because a deposit into a symbolic sr stays symbolic.
    !
    ! The value matters: 0x40000000 sets SR.MD (bit 30) and clears T.  Writing
    ! plain 0 would clear MD too, dropping a full-system emulator into user mode
    ! where the next privileged instruction faults.
    mov     #0x40, r1
    shll16  r1
    shll8   r1
    ldc     r1, sr

    bra     .Lmain
    nop                         ! Delay slot

    ! rts/n returns with *no* delay slot, so the poison instruction after it
    ! must never run.  A backend that wrongly gives rts/n a delay slot executes
    ! the poison and the folded result comes out negative instead.
.Lrtsn:
    rts/n
    mov     #-1, r0             ! Poison: must not execute

.Lmain:
    ! movi20 loads a 20-bit immediate in a single 32-bit instruction.  SH-4
    ! needs a PC-relative literal pool to do this at all.
    movi20  #0x12345, r0

    ! mulr multiplies straight into a general-purpose register rather than going
    ! through MACL.  Note the fixed R0 operand: mulr R0,Rn computes Rn *= R0.
    mov     #3, r1
    mulr    r0, r1              ! r1 = 3 * 0x12345 = 0x369cf

    ! movml.l Rm,@-R15 saves r0 through Rm - so r0-r14 here - and movml.l @r15+
    ! restores them.  (Its sibling movmu.l Rm,@-R15 saves the *upper* half,
    ! Rm through r14 plus pr, which is the form gcc -m2a emits in prologues.)  A
    ! backend that gets the register range or the direction backwards breaks
    ! every compiled SH-2A binary, so clobbering r14 in between proves the
    ! restore actually ran.
    movml.l r14, @-r15
    mov     #0, r14
    movml.l @r15+, r14

    ! Point r5 at scratch space well below sp, clear of the 60 bytes movml.l
    ! pushed and popped above, so the stores below cannot disturb the frame.
    mov     r15, r5
    add     #-64, r5

    ! movu.b zero-extends where mov.b sign-extends.  Storing 0xaa and reading it
    ! back both ways makes the difference observable: 0xaa - 0xffffffaa = 0x100.
    ! The displaced forms used here are themselves SH-2A 32-bit instructions.
    mov     #-86, r2            ! 0xaa
    mov.b   r2, @(1, r5)
    movu.b  @(1, r5), r3        ! 0x000000aa
    mov.b   @(1, r5), r6        ! 0xffffffaa
    sub     r6, r3              ! r3 = 0x100

    ! clips.b saturates a signed value into signed-byte range, so 0x369cf
    ! clamps to 0x7f.  Only the clamped value is checked: the hardware also
    ! sets T on saturation, but Ghidra's SH-2A sleigh does not model that side
    ! effect, and this test is not the place to litigate it.
    mov     r1, r7
    clips.b r7                  ! r7 = 0x7f

    ! nott inverts T, which the preamble left clear, so T becomes 1.  movt then
    ! reads it as 1 and movrt - which stores the *inverse* of T - reads 0.
    !
    ! The shll matters: movt and movrt are complements, so an unweighted
    ! r4 + r8 sums to 1 whichever way T went, and nott being a no-op, or movt and
    ! movrt being swapped, would still fold to the expected total.  Doubling one
    ! of them breaks that symmetry, so this really does constrain all three
    ! instructions - which is the entire point of a scenario meant to catch a
    ! backend treating SH-2A as SH-4.
    nott                        ! T = 1
    movt    r4                  ! r4 = 1
    movrt   r8                  ! r8 = 0
    shll    r8                  ! weight movrt x2: 0 here, 2 if T went the other way

    ! r0 = 0x369cf + 0x100 + 0x7f + 1 + (0 << 1) = 0x36b4f
    mov     r1, r0
    add     r3, r0
    add     r7, r0
    add     r4, r0
    add     r8, r0

    ! Set pr from inside the blob, then exercise rts/n above.  It returns to the
    ! instruction after this delay slot, from where execution falls off the end
    ! of the blob into the harness exit point.
    bsr     .Lrtsn
    nop                         ! Delay slot
