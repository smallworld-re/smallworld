    # zig cannot compile C for LoongArch32, so this is a hand-written
    # stand-in for exitpoint.elf.c, following exitpoint.tricore.elf.s.
    #
    # The harness runs `main` twice:
    #   * with an exit point at FAKE_EXITPOINT (0x10101010), which it also puts
    #     in `ra`, so the trailing `ret` lands there; and
    #   * with an exit point placed inside main's body, computed as
    #     main + sizeof(main) - mid_exit_offset, here the `ret`.
    # Both runs must leave 42 in a0.
    .text
    .globl _start
    .globl main
    .type _start, @function
    .type main, @function
_start:
main:
    li.w    $a0, 42
    ret
    .size main, .-main
    .size _start, .-_start
