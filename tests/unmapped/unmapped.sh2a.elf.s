    ! SH-2A stand-in for unmapped.elf.c - SuperH has no C compiler in this tree.
    ! Structurally identical to unmapped.sh4.elf.s so all three SuperH variants
    ! fault at the same address in the same way.
    !
    ! The harness enters each of read_unmapped / write_unmapped /
    ! fetch_unmapped in turn and expects the backend to report the
    ! corresponding unmapped-access failure.  0x8000 is the same address the C
    ! version uses: the ELF loads at 0x400000 and the harness's stack covers
    ! 0x2000..0x6000, so 0x8000 belongs to nothing.
    !
    ! 0x8000 is built with shifts rather than a PC-relative literal pool (which
    ! would land at the end of .text where it could be reached as code) and
    ! rather than SH-2A's `movi20`, so this file and the SH-4 one stay identical.
    ! `mov #imm` sign-extends its 8-bit immediate, so `mov #0x80` + `shll8`
    ! would produce 0xffff8000; 0x20 is positive, so `mov #0x20` + `shll8` +
    ! `shll2` gives exactly 0x8000.
    !
    ! Call-free by construction, nothing reads the T bit (SH-2A's T is the
    ! bitfield sr[0,1] rather than a register) and nothing is privileged, so no
    ! `ldc ..., sr` preamble is needed.
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
