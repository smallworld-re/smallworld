    ; Branches and calls: cjne in every form, djnz, jz, jnz, jc, jnc, sjmp,
    ; ajmp, ljmp, acall, lcall, ret and jmp @a+dptr.  Each records which way
    ; it went in internal RAM 0x3F.
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
    sjmp    .Lmain
.Lsub:
    inc     0x38
    ret
.Lmain:
    mov     0x3F, #0
    cjne    a, #0x80, .Lc1
    orl     0x3F, #0x01
.Lc1:
    SNAP    0x40
    cjne    a, 0x22, .Lc2
    orl     0x3F, #0x02
.Lc2:
    SNAP    0x42
    cjne    r2, #0x40, .Lc3
    orl     0x3F, #0x04
.Lc3:
    SNAP    0x44
    mov     r0, #0x36
    cjne    @r0, #0xC0, .Lc4
    orl     0x3F, #0x08
.Lc4:
    SNAP    0x46
    mov     r3, #5
    mov     0x30, #3
.Ld1:
    inc     0x31
    djnz    r3, .Ld1
.Ld2:
    inc     0x32
    djnz    0x30, .Ld2
    jz      .Lz
    orl     0x3F, #0x10
.Lz:
    jnz     .Lnz
    orl     0x3F, #0x20
.Lnz:
    jc      .Lcy
    orl     0x3F, #0x40
.Lcy:
    jnc     .Lncy
    orl     0x3F, #0x80
.Lncy:
    sjmp    .Ls
    mov     0x33, #0xEE     ; skipped
.Ls:
    ajmp    .La
    mov     0x34, #0xEE     ; skipped
.La:
    ljmp    .Ll
    mov     0x35, #0xEE     ; skipped
.Ll:
    acall   .Lsub
    lcall   .Lsub
    mov     dptr, #.Ljumps
    mov     a, r7
    anl     a, #0x02        ; entry 0 or 1, two bytes each
    jmp     @a+dptr
.Ljumps:
    sjmp    .Lj0
    sjmp    .Lj1
.Lj0:
    mov     0x37, #0x10
    sjmp    .Ldone
.Lj1:
    mov     0x37, #0x20
.Ldone:
    mov     a, 0x3F
    SNAP    0x48
    nop
