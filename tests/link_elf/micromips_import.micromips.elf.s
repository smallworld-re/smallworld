    # Imports foo from micromips_lib through a data reference, which LLD can
    # link for microMIPS where it cannot link a PIC call. Linked against the
    # library, fooref must point at foo with the ISA bit set.
    .set    micromips
    .text
    .globl  __start
    .type   __start, @function
    .ent    __start
__start:
    jrc     $ra
    .end    __start
    .size   __start, .-__start

    .data
    .globl  fooref
    .type   fooref, @object
fooref:
    .word   foo
    .size   fooref, .-fooref
