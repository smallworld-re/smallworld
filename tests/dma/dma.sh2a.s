    .text
test:
    ! Store both arguments to an MMIO register, then read the register back.
    !
    ! The MMIO address (0x50014000) is built with shifts and an `or` rather than
    ! loaded from a PC-relative literal pool.  SuperH's only 32-bit load of a
    ! constant is `mov.l @(disp,PC),Rn`, and the literal would have to sit past
    ! the last instruction - which is exactly where this scenario places its exit
    ! point, so the harness would try to execute the constant as code.
    mov     #0x50, r2
    shll8   r2
    add     #1, r2          ! r2 = 0x5001
    shll16  r2              ! r2 = 0x50010000
    mov     #0x40, r3
    shll8   r3              ! r3 = 0x4000
    or      r3, r2          ! r2 = 0x50014000

    mov.l   r4, @r2         ! MMIO[0] = first argument
    add     #4, r2
    mov.l   r5, @r2         ! MMIO[4] = second argument
    add     #4, r2
    mov.l   @r2, r0         ! result = MMIO[8]
