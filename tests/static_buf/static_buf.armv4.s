    .text
# Fake the PLT
foobar:
    # ARMv4 has no bkpt; the stubs are hooked, so any never-run word will do.
    # This one is permanently undefined on every ARM.
    .word 0xe7f000f0
test:
    # int *ret = foobar();
    bl      foobar
    # return *ret;
    ldr     r0, [r0]
