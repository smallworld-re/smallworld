    ! SuperH has no C compiler in this tree, so this is a hand-written stand-in
    ! for exitpoint.elf.c, following tests/exitpoint/exitpoint.tricore.elf.s.
    !
    ! Built for both SH-4 variants: SH4EL_SRC_EXT := $(SH4_EXT) in tests/Makefile
    ! assembles this same file with -little for sh4el.
    !
    ! The harness runs `main` twice:
    !   * with an exit point at FAKE_EXITPOINT (0x10101010), which it also puts
    !     in `pr`, so the trailing `rts` lands there; and
    !   * with an exit point placed inside main's body, computed as
    !     main + sizeof(main) - mid_exit_offset.
    ! Both runs must leave 42 in r0.
    !
    ! Deliberately call-free: Ghidra's SuperH4.sinc never assigns PR on
    ! bsr/jsr, so anything that had to *produce* a return address would be
    ! broken on angr and pcode.  Reading a pre-seeded `pr` with `rts` works on
    ! every backend.
    !
    ! Nothing here reads the T bit, and every instruction is unprivileged, so no
    ! `ldc ..., sr` preamble is needed (see tests/strlen/strlen.sh2a.s for the
    ! case that does).  No PC-relative literal pool either: `mov #42` covers the
    ! whole constant, so nothing that is really data can be reached as code.
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
