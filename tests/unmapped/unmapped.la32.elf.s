    # zig cannot compile C for LoongArch32, so this is a hand-written
    # stand-in for unmapped.elf.c, following unmapped.tricore.elf.s: one
    # function each to read, write and fetch the unmapped address 0x8000.
    .text
    .globl _start
    .type _start, @function
_start:
    ret
    .size _start, .-_start

    .globl read_unmapped
    .type read_unmapped, @function
read_unmapped:
    lu12i.w $t0, 0x8
    ld.w    $a0, $t0, 0
    ret
    .size read_unmapped, .-read_unmapped

    .globl write_unmapped
    .type write_unmapped, @function
write_unmapped:
    lu12i.w $t0, 0x8
    li.w    $t1, 42
    st.w    $t1, $t0, 0
    ret
    .size write_unmapped, .-write_unmapped

    .globl fetch_unmapped
    .type fetch_unmapped, @function
fetch_unmapped:
    lu12i.w $t0, 0x8
    jr      $t0
    .size fetch_unmapped, .-fetch_unmapped
