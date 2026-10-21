    .text
_start:
    call    foo
     nop
bar:
    ! A windowed callee: the caller's %o0 arrives in %i0, and the result
    ! goes back to the caller's %o0 through %i0 when `restore` rotates the
    ! window back.
    save    %sp, -96, %sp
    cmp     %i0, 101
    bge     .L2
     sll    %i0, 3, %l0     ! delay slot: runs whether or not the branch is taken
    ba      .L3
     mov    %l0, %i0
.L2:
    mov     32, %i0
.L3:
    ret
     restore
foo:
    sub     %o0, 1, %o0
    call    bar
     nop
    add     %o0, 1, %o0
