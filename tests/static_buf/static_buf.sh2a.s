    .text
foobar:
    ! Placeholder the harness hooks with a model that hands back a buffer
    ! address in r2.  Four bytes, so `test` lands at offset 4 and the spec's
    ! entry_offset matches the other architectures.
    .long   0
test:
    bsr     foobar
    nop                     ! delay slot, executed before the branch is taken
    mov.l   @r2, r0         ! load through the address the model provided
