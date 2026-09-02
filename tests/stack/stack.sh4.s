    .text
manyargs:
    ! The SH ABI passes the first four integer arguments in r4-r7 and spills the
    ! rest; the harness leaves the single spilled argument at [sp].  Sum it with
    ! the first and third register arguments into the return register r0.
    mov.l   @r15, r0
    add     r4, r0
    add     r6, r0
