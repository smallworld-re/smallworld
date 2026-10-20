    .syntax unified
    .thumb
    .text
_start:
        bl      foo
bar:
        # Thumb's push/pop reach only r0-r7 and lr/pc, so r7 is the frame pointer.
        push    {r7, lr}
        movs    r1, #8
        muls    r1, r0, r1
        cmp     r0, #101
        mov     r0, r1
        blt     .L2
        movs    r0, #32
.L2:
        pop     {r7, pc}
foo:
        subs    r0, r0, #1
        bl      bar
        adds    r0, r0, #1
