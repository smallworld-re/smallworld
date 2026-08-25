    ! SH-2A stand-in for exitpoint.elf.c - SuperH has no C compiler in this tree.
    ! Structurally identical to exitpoint.sh4.elf.s (same instructions, same
    ! sizes) so a single mid_exit_offset covers sh2a, sh4 and sh4el.
    !
    ! The harness runs `main` twice:
    !   * with an exit point at FAKE_EXITPOINT (0x10101010), which it also puts
    !     in `pr`, so the trailing `rts` lands there; and
    !   * with an exit point placed inside main's body, computed as
    !     main + sizeof(main) - mid_exit_offset.
    ! Both runs must leave 42 in r0.
    !
    ! Deliberately call-free: reading a pre-seeded `pr` with `rts` behaves the
    ! same on every backend, whereas producing a return address depends on the
    ! bsr/jsr PR semantics that differ between sleigh specs.
    !
    ! Nothing here reads the T bit (SH-2A's T is the bitfield sr[0,1], not a
    ! register, so a symbolic-state backend would otherwise carry an
    ! unconstrained `sr` into the result), and every instruction is unprivileged,
    ! so no `ldc ..., sr` preamble is needed.  No PC-relative literal pool
    ! either: `mov #42` covers the whole constant, so no data can be reached as
    ! code when the exit point moves.
    .text
    .globl _start
    .globl main
    .type _start, @function
    .type main, @function
_start:
main:
    mov     #42, r0
    rts
    nop          ! Delay slot
    .size main, .-main
    .size _start, .-_start
