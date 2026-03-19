    .text
foobar:
    trap #0
test:
    # Set up the stack
    link.w  %fp, #0

    # int *ret = foobar();
    bsr     foobar

    # return *ret
    move.l 0(%a0), %d0
    
    # Clean up the stack
    unlk    %fp
