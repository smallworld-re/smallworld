# Dynamic taint-tracking exercise (MIPS; also built little-endian for mipsel).
#
# Inputs (set by the harness):
#   $4  (a0) = taint source "a"
#   $5  (a1) = taint source "b"
#   $7  (a3) = pointer to an 8-byte scratch buffer (taint source "ptr")
#   $9  (t1) = taint source "clearme"
#
# Exercises arithmetic taint union, register->memory store, memory->register
# load, and a taint-clearing idiom.
    .text
    addu    $6, $4, $5      # a2 <- a + b
    sw      $6, 0($7)       # store a | b to the buffer
    lw      $8, 0($7)       # load it back into t0
    xor     $9, $9, $9      # clears t1's taint
