@ Dynamic taint-tracking exercise (ARM, hard-float target).
@
@ Inputs (set by the harness):
@   r0 = taint source "a"
@   r1 = taint source "b"
@   r2 = pointer to an 8-byte scratch buffer (taint source "ptr")
@   r5 = taint source "clearme"
@
@ Exercises arithmetic taint union, register->memory store, memory->register
@ load, and a taint-clearing idiom.
    .text
    add     r3, r0, r1      @ r3 <- a + b
    str     r3, [r2]        @ store a | b to the buffer
    ldr     r4, [r2]        @ load it back into r4
    eor     r5, r5, r5      @ clears r5's taint
