    .text
# NOTE: This uses what's known as the "call0" ABI.
#
# This acts a lot like ARM and others,
# where you need to save and restore your own
# link register and frame pointer (a0 and a15),
# probably using the stack
#
# XTensa also has a "windowed" ABI,
# which uses optional instructions
# to use register aliasing to preserve
# caller state.
# The open source assembler doesn't support
# the windowed register option.

_start:
    call0   foo
    .byte   0x00
bar:
    movi    $a3, 8
    mull    $a3, $a2, $a3
    movi    $a4, 101
    bge     $a2, $a4, .L2
    mov     $a2, $a3
    j       .L3
.L2:
    movi    $a2, 32
.L3:
    ret
foo:
    addi    $a2, $a2, -1
    call0   bar
    addi    $a2, $a2, 1
