# Fake the PLT.
foobar:
    int3
test:
    # Set up the stack
    push    %ebp
    mov     %esp,%ebp

    # int *ret = foobar();
    call    foobar

    # return *ret;
    mov     (%eax),%eax
    
    # Clean up the stack
    pop     %ebp
