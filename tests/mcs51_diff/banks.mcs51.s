    ; Register banks: R0-R7 are internal RAM 0x00-0x1F, in the bank PSW's RS
    ; bits select.  Copy and save registers through their addresses, as
    ; SDCC's code does (mov ar2,r7; push ar7), switch banks, and reach a
    ; bank's registers both by name and through memory.
    ; Part of the mcs51_diff scenario; see harness/scenarios/mcs51_diff.py.
    ; It starts from a random state (registers, PSW flags, internal RAM
    ; 0x20-0xFF and XDATA 0x0000-0x00FF) and the scenario compares where it
    ; ends against ucsim_51.  SNAP saves A and PSW to internal RAM.

    .macro SNAP slot
    mov     slot, a
    mov     slot+1, psw
    .endm

    .area CSEG (CODE)
_start:
    mov     r7, #0x11
    mov     0x02, r7        ; R2 = R7, through R2's address (SDCC's ar2)
    mov     a, r2
    SNAP    0x40
    push    0x07            ; save R7 through its address (SDCC's push ar7)
    mov     r7, #0x22
    pop     0x07            ; and restore it
    mov     a, r7
    SNAP    0x42
    mov     0x05, #0x33     ; R5 through its address
    mov     a, r5
    SNAP    0x44
    mov     psw, #0x08      ; bank 1: R0-R7 are internal RAM 0x08-0x0F
    mov     a, r7           ; bank 1's R7, from its random starting byte
    SNAP    0x46
    mov     r7, #0x44
    mov     r0, #0x0F       ; bank 1's own R0 points at its R7
    mov     a, @r0
    SNAP    0x48
    inc     @r0             ; R7 through memory
    mov     a, r7
    SNAP    0x4A
    mov     psw, #0x10      ; bank 2
    mov     r3, 0x0F        ; bank 2's R3 = bank 1's R7
    xch     a, r3
    SNAP    0x4C
    orl     psw, #0x08      ; bank 3, by setting RS0
    djnz    r1, .Lbank3
.Lbank3:
    mov     a, r1
    SNAP    0x4E
    mov     a, 0x1A         ; bank 3's R2, through memory
    add     a, r2
    SNAP    0x50
    anl     psw, #0xE7      ; back to bank 0
    mov     a, r7           ; still 0x11
    add     a, r2
    add     a, r5
    SNAP    0x52
    mov     psw, #0x10      ; end in bank 2
    nop
