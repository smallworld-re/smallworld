    .text
# Fake the PLT
foobar:
    brk 0
test:
    # int *ret = foobar()
    bl  foobar
    # return *ret
    ldr w0, [x0]
