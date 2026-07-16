// Dynamic taint-tracking exercise (AArch64).
//
// Inputs (set by the harness):
//   x0 = taint source "a"
//   x1 = taint source "b"
//   x2 = pointer to an 8-byte scratch buffer (taint source "ptr")
//   x5 = taint source "clearme"
//
// Exercises arithmetic taint union, register->memory store, memory->register
// load, and a taint-clearing idiom.
    .text
    add     x3, x0, x1      // x3 <- a + b
    str     x3, [x2]        // store a | b to the buffer
    ldr     x4, [x2]        // load it back into x4
    eor     x5, x5, x5      // clears x5's taint
