    .text
    ! The dr/fr register overlay, the SH-2A 32-bit floating-point memory forms,
    ! and the single<->double round trip through FPUL.
    !
    ! SuperH defines DRn as the pair FRn:FRn+1 with FRn the *upper* half, and
    ! every backend here models that differently underneath: Ghidra's sleigh
    ! declares fr and dr at overlapping register-space offsets, QEMU keeps a flat
    ! `float32 fregs[32]` and synthesises dr from adjacent entries, and Styx
    ! exposes only the dr pair as a real register.  Three representations of one
    ! architectural fact is exactly where a backend gets it backwards, so this
    ! blob checks the overlay from *inside* the guest - via flds/sts into
    ! general-purpose registers - rather than trusting the harness's register
    ! model.  The runner separately asserts the harness-visible composition.
    !
    ! The runner sets FPSCR = 0x00040001 (PR=0 single, SZ=0) before entry.  SZ
    ! matters here: `fmov.s` and `fmov.d` displaced forms are *encoding
    ! identical* - they share word-2 selectors 3 and 7 and are told apart only by
    ! FPSCR.SZ, with the displacement scaled by 4 or 8 respectively.  objdump
    ! cannot tell them apart either and will print these as `fmov.d`.  With SZ=0
    ! the `fmov.s` spelling below is the one that matches at runtime.
    !
    ! Inputs, set by the runner:
    !   dr0  = 0x3ff0000000000001   (deliberately asymmetric halves)
    !   dr2  = 0.75                 (exact in both binary32 and binary64)
    !   fr6  = 0x0badf00d           (raw bits; never interpreted as a float)
    !   fr10 = 0x11112222, fr11 = 0x33334444   (untouched; composition check)
sh2a_fpu_overlay:
    ! *** The overlay, as the guest sees it ***
    ! flds moves raw bits, so this reads the two halves of dr0 without any
    ! floating-point interpretation.  fr0 must be the high half.
    flds    fr0, fpul
    sts     fpul, r1            ! r1 = 0x3ff00000
    flds    fr1, fpul
    sts     fpul, r2            ! r2 = 0x00000001

    ! *** SH-2A's 32-bit displaced floating-point moves ***
    ! These encodings do not exist on SH-1..SH-4 at all; they are two of the
    ! twenty-four 32-bit forms SH-2A adds.  Round-tripping through memory proves
    ! the displacement scaling (by 4, because SZ=0) as well as the transfer.
    mov     r15, r7
    add     #-64, r7            ! scratch, well clear of the frame
    fmov.s  fr6, @(16, r7)
    fmov.s  @(16, r7), fr7      ! fr7 = fr6

    ! *** The ordinary floating-point memory forms ***
    ! Indirect, post-increment and pre-decrement, sharing one scratch slot.
    fmov.s  fr6, @r7            ! [r7]      = fr6
    fmov.s  @r7, fr8            ! fr8       = fr6
    fmov.s  @r7+, fr9           ! fr9       = fr6, r7 += 4
    fmov.s  fr6, @-r7           ! r7 -= 4, [r7] = fr6  (r7 back where it started)

    ! *** single <-> double round trip, switching precision mid-blob ***
    ! Each FPSCR word is built with movi20s + add, which needs no PC-relative
    ! literal pool.
    !
    ! Two things to know about these immediates.  movi20's is *signed* 20-bit, so
    ! a bare `movi20 #0xc0001` is rejected as out of range: bit 19 is set, making
    ! it a negative literal that would sign-extend to 0xfffc0001.  And movi20s
    ! takes the *final* value, not the pre-shift field - the assembler encodes
    ! value>>8 and the value must therefore be a multiple of 256, which is why
    ! the low bit comes from the add.
    movi20s #0xc0000, r3
    add     #1, r3              ! r3 = 0x000c0001
    lds     r3, fpscr           ! PR = 1: double
    fcnvds  dr2, fpul           ! fpul = binary32(0.75) = 0x3f400000
    sts     fpul, r4
    fcnvsd  fpul, dr4           ! dr4  = binary64(0.75)
    movi20s #0x40000, r5
    add     #1, r5              ! r5 = 0x00040001
    lds     r5, fpscr           ! PR = 0 again, so the final FPSCR is known
