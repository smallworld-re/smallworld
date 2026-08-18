    .text
foobar:
    ! Placeholder the harness hooks with a model that hands back a buffer
    ! address in r2.  Four bytes, so `test` lands at offset 4 and the spec's
    ! entry_offset matches the other architectures.
    .long   0
test:
    ! Deliberately `bsr`, matching the SH-2A source: the model returns through
    ! `pr`, and this is the scenario that exercises the bsr path.  Real
    ! hardware and PANDA's QEMU both leave pr = inst_start + 4 here, but
    ! Ghidra's SuperH4.sinc `:bsr` never assigns PR at all, so angr and pcode
    ! cannot return from this call and are skipped in static_buf.py with a
    ! measured reason.  (`jsr @Rn` would work on all three - sleigh's `:jsr`
    ! does write PR - and that is what tests/hooking/hooking.sh4.s uses, so the
    ! two scenarios between them cover both call forms.)
    bsr     foobar
    nop                     ! delay slot, executed before the branch is taken
    mov.l   @r2, r0         ! load through the address the model provided
