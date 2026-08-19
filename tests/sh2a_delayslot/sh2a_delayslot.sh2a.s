    .text
    ! Conditional delayed branches: bt/s and bf/s.
    !
    ! These are in the platform definition's delay_slot_mnemonics and had no
    ! coverage anywhere in the suite.  They are worth testing because the Renesas
    ! pseudocode is easy to misread as suppressing the delay slot when the branch
    ! is not taken, whereas both independent implementations execute it
    ! unconditionally and only make the *branch* conditional:
    !
    !   QEMU   target/sh4/translate.c, case 0x8d00: latches the condition into
    !          cpu_delayed_cond, sets TB_FLAG_DELAY_SLOT_COND and returns, so the
    !          delay slot is then decoded and executed like any instruction;
    !          gen_delayed_conditional_jump branches afterwards.
    !   Ghidra superh.sinc: `local cond = T; delayslot(1); if (cond) goto ...`.
    !
    ! Both latch the condition *before* running the delay slot, which is what the
    ! third case below pins down.
    !
    ! Takes no input; every result is a fixed integer, so this blob is also
    ! meaningful to compare across backends.
sh2a_delayslot:
    ! === A: bt/s NOT taken - the delay slot must still execute ===
    ! A backend that suppresses the delay slot on the not-taken path leaves
    ! r1 = 10 instead of 11.  One that takes the branch anyway leaves r1 = -1.
    mov     #0, r0
    cmp/eq  #1, r0              ! T = (r0 == 1) = 0
    mov     #0, r1
    bt/s    .Lbad_a             ! T = 0, so NOT taken
    add     #1, r1              ! delay slot: runs regardless -> r1 = 1
    add     #10, r1             ! fall-through -> r1 = 11
    bra     .Lb
    nop                         ! delay slot
.Lbad_a:
    mov     #-1, r1             ! must never execute
.Lb:
    ! === B: bf/s taken - the delay slot clobbers the compare's source ===
    ! r0 is what cmp/eq read, and the delay slot overwrites it after the branch
    ! decision has been made.  The branch must still be taken.
    mov     #0, r0
    cmp/eq  #1, r0              ! T = 0, so bf/s IS taken
    mov     #0, r2
    bf/s    .Ltaken_b
    mov     #99, r0             ! delay slot: clobbers the condition's source
    mov     #-1, r2             ! must never execute
.Ltaken_b:
    add     #5, r2              ! r2 = 5

    ! === C: bt/s taken - the delay slot flips T itself ===
    ! The strongest form of the same point.  nott inverts T *after* the branch
    ! condition was latched, so a backend that re-reads T when it resolves the
    ! branch would wrongly fall through and leave r3 = -1 + 7 = 6.
    mov     #1, r0
    cmp/eq  #1, r0              ! T = 1, so bt/s IS taken
    mov     #0, r3
    bt/s    .Ltaken_c
    nott                        ! delay slot: T becomes 0
    mov     #-1, r3             ! must never execute
.Ltaken_c:
    add     #7, r3              ! r3 = 7

    ! T must still show the delay slot's effect, proving it really ran.
    movt    r4                  ! r4 = 0
    nop
