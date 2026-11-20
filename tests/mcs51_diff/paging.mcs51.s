    ; External RAM through MOVX @Ri, whose address takes its high byte from
    ; P2, as SDCC's startup code and pdata rely on.  Bytes move between pages
    ; 1-3, reached both through DPTR and through @Ri, and internal RAM, where
    ; the scenario compares them; a write to the wrong page lands in page 0,
    ; which it compares too.
    ; Part of the mcs51_diff scenario; see harness/scenarios/mcs51_diff.py.
    ; It starts from a random state (registers, PSW flags, internal RAM
    ; 0x20-0xFF and XDATA 0x0000-0x00FF) and the scenario compares where it
    ; ends against ucsim_51.

    .area CSEG (CODE)
    ; Write pages 1 and 2 through DPTR, and read them back through @r0.
    mov     dptr, #0x0123
    mov     a, #0x5A
    movx    @dptr, a
    mov     dptr, #0x0223
    mov     a, #0xA5
    movx    @dptr, a
    mov     0xA0, #0x01     ; P2: page 1
    mov     r0, #0x23
    movx    a, @r0
    mov     0x40, a         ; 0x5A
    mov     0xA0, #0x02     ; page 2
    movx    a, @r0
    mov     0x41, a         ; 0xA5

    ; Write page 3 through @r1, and read it back through DPTR.
    mov     0xA0, #0x03
    mov     r1, #0x80
    mov     a, #0x3C
    movx    @r1, a
    mov     dptr, #0x0380
    movx    a, @dptr
    mov     0x42, a         ; 0x3C

    ; Page 0 kept its byte at 0x80, and still takes writes.
    mov     0xA0, #0x00
    movx    a, @r1
    mov     0x43, a
    mov     a, #0x77
    movx    @r1, a

    ; Step P2 across a page boundary, as SDCC's startup code does.
    mov     0xA0, #0x01
    mov     r0, #0xFF
    mov     a, #0x11
    movx    @r0, a          ; 0x01FF
    inc     r0
    inc     0xA0
    mov     a, #0x22
    movx    @r0, a          ; 0x0200
    mov     dptr, #0x01FF
    movx    a, @dptr
    mov     0x44, a         ; 0x11
    inc     dptr
    movx    a, @dptr
    mov     0x45, a         ; 0x22
    nop
