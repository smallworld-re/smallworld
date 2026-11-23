    .text
test:
    ! Tests single-stepping delay slot instructions
    ! If the branches are not taken correctly,
    ! the return value will be incorrect.

    ! Set a flag so I can use a conditional branch      ! 0x1000
    mov     1, %g2
    ! Set an address so I can dereference               ! 0x1004
    sethi   %hi(0x2000), %g3

    mov     1, %o0                                      ! 0x1008
    ba      .L1                                         ! 0x100c
     st     %o0, [%g3]                                  ! 0x1010

    ! Dead block
    mov     -1, %o0                                     ! 0x1014
    st      %o0, [%g3]                                  ! 0x1018

.L1:
    add     %o0, 1, %o0                                 ! 0x101c
    cmp     %g2, 0                                      ! 0x1020
    be      .L2                                         ! 0x1024
     st     %o0, [%g3]                                  ! 0x1028

    ba      .L1                                         ! 0x102c
     mov    0, %g2                                      ! 0x1030

    ! Dead block
    mov     -1, %o0                                     ! 0x1034

.L2:
    add     %o0, 1, %o0                                 ! 0x1038
    st      %o0, [%g3]                                  ! 0x103c
