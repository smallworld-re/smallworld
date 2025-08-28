    .text
# Fake the PLT
foobar:
    ill.n
    ill.n
test:
    # int *ret = foobar();
    call0   foobar

    # return *ret;
    l32i    $a2, $a2, 0
    nop
