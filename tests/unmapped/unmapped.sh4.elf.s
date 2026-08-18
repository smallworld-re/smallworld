    ! SuperH has no C compiler in this tree, so this is a hand-written stand-in
    ! for unmapped.elf.c, following tests/unmapped/unmapped.tricore.elf.s.
    !
    ! Built for both SH-4 variants: SH4EL_SRC_EXT := $(SH4_EXT) in tests/Makefile
    ! assembles this same file with -little for sh4el.
    !
    ! The harness enters each of read_unmapped / write_unmapped /
    ! fetch_unmapped in turn and expects the backend to report the
    ! corresponding unmapped-access failure.  0x8000 is the same address the C
    ! version uses: the ELF loads at 0x400000 and the harness's stack covers
    ! 0x2000..0x6000, so 0x8000 belongs to nothing.
    !
    ! 0x8000 is built with shifts rather than a PC-relative literal pool: a pool
    ! would land at the end of .text where it could be reached as code, and
    ! `mov #imm` sign-extends its 8-bit immediate, so `mov #0x80` + `shll8`
    ! would produce 0xffff8000 instead.  0x20 is positive, so `mov #0x20` +
    ! `shll8` + `shll2` gives exactly 0x8000.
    !
    ! Call-free by construction: nothing needs a return address to be produced,
    ! so Ghidra's SuperH4.sinc bsr/jsr PR bug is not in play.  Nothing reads the
    ! T bit and nothing is privileged, so no `ldc ..., sr` preamble is needed.
    .text
    .globl _start
    .type _start, @function
_start:
    ! Never entered by the harness; present only so `ld` finds an entry symbol.
    rts
    nop          ! Delay slot
    .size _start, .-_start

    .globl read_unmapped
    .type read_unmapped, @function
read_unmapped:
    mov     #0x20, r1
    shll8   r1           ! r1 = 0x2000
    shll2   r1           ! r1 = 0x8000
    mov.l   @r1, r0
    rts
    nop          ! Delay slot
    .size read_unmapped, .-read_unmapped

    .globl write_unmapped
    .type write_unmapped, @function
write_unmapped:
    mov     #0x20, r1
    shll8   r1           ! r1 = 0x2000
    shll2   r1           ! r1 = 0x8000
    mov     #42, r0
    mov.l   r0, @r1
    rts
    nop          ! Delay slot
    .size write_unmapped, .-write_unmapped

    .globl fetch_unmapped
    .type fetch_unmapped, @function
fetch_unmapped:
    mov     #0x20, r1
    shll8   r1           ! r1 = 0x2000
    shll2   r1           ! r1 = 0x8000
    jmp     @r1
    nop          ! Delay slot - runs before the branch is taken
    .size fetch_unmapped, .-fetch_unmapped
