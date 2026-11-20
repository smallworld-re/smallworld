    # A microMIPS shared library for the ELF loader's ISA-bit handling.
    # LLD gives foo an odd value in .dynsym and an even one in .symtab, and
    # fooptr an R_MIPS_REL32 against foo, which must come out odd.
    .set    micromips
    .text
    .globl  foo
    .type   foo, @function
    .ent    foo
foo:
    jrc     $ra
    .end    foo
    .size   foo, .-foo

    .data
    .globl  fooptr
    .type   fooptr, @object
fooptr:
    .word   foo
    .size   fooptr, .-fooptr
