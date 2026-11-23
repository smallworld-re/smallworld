    # V850 stand-in for unmapped.elf.c: there is no V850 C compiler in this
    # tree. The harness enters each of read_unmapped, write_unmapped and
    # fetch_unmapped in turn and expects the backend to report the matching
    # unmapped-access failure; it checks the kind of failure, not its
    # address. 0x8000 is the address the C version uses.
    #
    # movea sign-extends its 16-bit immediate, so 0x8000 needs movhi too;
    # hi() rounds up to make up for lo()'s sign extension.
    .text
    .globl _start
    .type _start, @function
_start:
    # Never entered by the harness; present only so ld finds an entry symbol.
    jmp     [lp]
    .size _start, .-_start

    .globl read_unmapped
    .type read_unmapped, @function
read_unmapped:
    movhi   hi(0x8000), r0, r11
    movea   lo(0x8000), r11, r11
    ld.w    0[r11], r10
    jmp     [lp]
    .size read_unmapped, .-read_unmapped

    .globl write_unmapped
    .type write_unmapped, @function
write_unmapped:
    movhi   hi(0x8000), r0, r11
    movea   lo(0x8000), r11, r11
    mov     10, r10
    st.w    r10, 0[r11]
    jmp     [lp]
    .size write_unmapped, .-write_unmapped

    .globl fetch_unmapped
    .type fetch_unmapped, @function
fetch_unmapped:
    movhi   hi(0x8000), r0, r11
    movea   lo(0x8000), r11, r11
    jmp     [r11]
    .size fetch_unmapped, .-fetch_unmapped
