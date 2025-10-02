    .text
test:
    # xtensa's syscall ABI is a) different from its function call ABI,
    # and b) weird.
    # The syscall number goes into a2,
    # then the arg registers are, in order, a6, a3, a4, a5, a8, a9.
    # Don't look at me; I just work here :p
    mov     $a6, $a2 
    movi    $a2, 0x4
    syscall
    nop
    nop
