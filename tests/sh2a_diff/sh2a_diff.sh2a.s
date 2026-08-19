    .text
    ! Differential blob: run on every available backend, with *full* register
    ! state compared engine-against-engine rather than one register checked per
    ! engine.
    !
    ! Deliberately integer-only and deliberately SH-2A-heavy.  Floating point is
    ! excluded because the backends are known to disagree there for reasons that
    ! have nothing to do with this blob - angr's pcode engine implements no FP at
    ! all, and Ghidra's SH-2A sleigh ignores FPSCR.PR - and a comparison that is
    ! expected to fail teaches nothing.  The FPU is covered by the sh2a_fpu*
    ! scenarios instead.
    !
    ! What agreement here proves: four independent decoders - Ghidra's sleigh, the
    ! same sleigh via angr, Styx's SuperH2A core, and a QEMU target/sh4 patched by
    ! hand - produce bit-identical machine state for SH-2A's own instruction set.
    ! For the QEMU patch that is the strongest available check, because it has no
    ! other independent oracle.
    !
    ! Every value is derived from constants in the blob, so there is nothing to
    ! seed and no dependence on harness register-initialisation order.  There is
    ! no data at the end: a literal pool would sit exactly where the harness puts
    ! its exit point and would be executed as code.
sh2a_diff:
    ! *** 20-bit immediates: SH-2A's alternative to a PC-relative literal pool ***
    ! movi20 sign-extends its 20-bit field, movi20s shifts the (also signed) field
    ! left by 8.  #-1 is the interesting one: a backend that masks to 20 bits
    ! instead of sign-extending yields 0x000fffff here rather than 0xffffffff.
    movi20  #0x12345, r1        ! r1 = 0x00012345
    movi20  #-1, r2             ! r2 = 0xffffffff
    movi20s #0x40000, r3        ! r3 = 0x00040000

    ! *** mulr: multiply into a general-purpose register, no MACL detour ***
    ! The multiplier is fixed at R0 by the encoding: mulr R0,Rn computes Rn *= R0.
    mov     #3, r0
    mov     r1, r4
    mulr    r0, r4              ! r4 = 0x12345 * 3 = 0x369cf

    ! *** Saturating clips/clipu, all four widths ***
    ! 0x369cf is out of range for every one of them, so the saturating path is
    ! taken each time.  SR is deliberately *not* compared across engines: SH-2A's
    ! T bit is sr[0,1], QEMU keeps M/Q/T in separate fields recombined only by an
    ! exported accessor, and Ghidra's sleigh does not model the CS side effect at
    ! all - three legitimate representations of one register.
    mov     r4, r5
    clips.b r5                  ! r5 = 0x0000007f
    mov     r4, r6
    clips.w r6                  ! r6 = 0x00007fff
    mov     r4, r7
    clipu.b r7                  ! r7 = 0x000000ff
    mov     r4, r8
    clipu.w r8                  ! r8 = 0x0000ffff

    ! *** divs / divu: SH-2A's single-instruction divide ***
    ! Both take the divisor in R0, still 3.  0x369cf / 3 = 0x12345 exactly, so
    ! the signed and unsigned forms must agree and neither reaches the cases the
    ! architecture leaves undefined.
    mov     r4, r9
    divs    r0, r9              ! r9  = 0x00012345
    mov     r4, r10
    divu    r0, r10             ! r10 = 0x00012345

    ! *** Register bit manipulation ***
    ! bset writes a bit, bld reads one into T, bst writes T back out.  Sequenced
    ! so T is always written before it is read - no reliance on the incoming SR,
    ! which a symbolic backend would leave unconstrained.
    !
    ! `bclr #imm3,Rn` is deliberately absent, and covered by sh2a_bitreg instead:
    ! it is broken in the sleigh that pypcode 3.3.3 and Styx bundle, so including
    ! it here would knock two of the four backends out of a comparison whose
    ! whole purpose is to span them.  See sh2a_bitreg for the diagnosis.
    mov     #0, r11
    bset    #5, r11             ! r11 = 0x20
    bset    #1, r11             ! r11 = 0x22
    bld     #1, r11             ! T = bit1 = 1
    mov     #0, r12
    bst     #7, r12             ! r12 = 0x80   (T -> bit 7)
    nott                        ! T = 0
    bst     #6, r12             ! r12 = 0x80   (bit 6 <- 0)
    movt    r13                 ! r13 = 0
    movrt   r14                 ! r14 = 1      (the inverse of T)

    ! *** TBR: the SH-2A table base register ***
    ! A plain ldc/stc round trip through a register the earlier steps are done
    ! with.  R0 is reused last, once divs/divu no longer need the divisor.
    movi20  #0x5a5a0, r0
    ldc     r0, tbr
    mov     #0, r0
    stc     tbr, r0             ! r0 = 0x0005a5a0

    ! Fall off the end into the harness's exit point.  No rts, and nothing but
    ! instructions in the blob.
    nop
