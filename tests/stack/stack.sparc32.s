    .text
manyargs:
    ! Add args 1, 3 and 5 (%o0, %o2, %o4) and arg 7.  Args 1-6 travel in
    ! %o0-%o5; arg 7 is the first on the stack, past the 64-byte window save
    ! area, the hidden struct-return word and the six argument words.
    add     %o0, %o2, %o0
    add     %o0, %o4, %o0
    ld      [%sp + 92], %o1
    add     %o0, %o1, %o0
