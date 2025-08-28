    .text
# Fake the PLT
foobar:
    bkpt
test:
    # int *ret = foobar();
    bl      foobar
    # return *ret;
    ldr     r0, [r0]
