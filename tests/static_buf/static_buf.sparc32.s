    .text
! Fake the PLT; the harness models foobar at offset 0.
foobar:
    unimp   0
test:
    ! int *ret = foobar();
    call    foobar
     nop
    ! return *ret;
    ld      [%o0], %o0
