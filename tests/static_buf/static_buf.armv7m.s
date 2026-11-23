    .syntax unified
    .thumb
    .text
# Fake the PLT; the nop keeps `test` at offset 4, where the harness enters
foobar:
    bkpt
    nop
test:
    # int *ret = foobar();
    bl      foobar
    # return *ret;
    ldr     r0, [r0]
