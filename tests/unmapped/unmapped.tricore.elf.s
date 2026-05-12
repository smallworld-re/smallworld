    .text
    .globl _start
    .type _start, @function
_start:
    ji      %a11
    .size _start, .-_start

    .globl read_unmapped
    .type read_unmapped, @function
read_unmapped:
    mov.u   %d2, 0x8000
    mov.a   %a2, %d2
    ld.w    %d2, [%a2]0
    ji      %a11
    .size read_unmapped, .-read_unmapped

    .globl write_unmapped
    .type write_unmapped, @function
write_unmapped:
    mov.u   %d2, 0x8000
    mov.a   %a2, %d2
    mov     %d2, 42
    st.w    [%a2]0, %d2
    ji      %a11
    .size write_unmapped, .-write_unmapped

    .globl fetch_unmapped
    .type fetch_unmapped, @function
fetch_unmapped:
    mov.u   %d2, 0x8000
    mov.a   %a2, %d2
    ji      %a2
    .size fetch_unmapped, .-fetch_unmapped
