    .text
    ! SH-2 port of sh2a_delayslot.sh2a.s: conditional delayed branches, bt/s
    ! and bf/s, which SH-2 introduced.  SH-1 has neither, so the Makefile keeps
    ! this file out of the SH-1 build; superh_isa checks that SH-1 refuses them.
    !
    ! Identical to the SH-2A blob except in case C, where SH-2A's `nott` (an
    ! SH-2A addition) becomes `clrt`.  The point is unchanged: the delay slot
    ! clears T *after* the branch condition was latched.  See the SH-2A file
    ! for why the delay slot runs whether or not the branch is taken.
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
    mov     #0, r0
    cmp/eq  #1, r0              ! T = 0, so bf/s IS taken
    mov     #0, r2
    bf/s    .Ltaken_b
    mov     #99, r0             ! delay slot: clobbers the condition's source
    mov     #-1, r2             ! must never execute
.Ltaken_b:
    add     #5, r2              ! r2 = 5

    ! === C: bt/s taken - the delay slot clears T itself ===
    ! A backend that re-reads T when it resolves the branch would wrongly fall
    ! through and leave r3 = -1 + 7 = 6.
    mov     #1, r0
    cmp/eq  #1, r0              ! T = 1, so bt/s IS taken
    mov     #0, r3
    bt/s    .Ltaken_c
    clrt                        ! delay slot: T becomes 0
    mov     #-1, r3             ! must never execute
.Ltaken_c:
    add     #7, r3              ! r3 = 7

    ! T must still show the delay slot's effect, proving it really ran.
    movt    r4                  ! r4 = 0
    nop
