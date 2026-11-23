    .syntax unified
    .thumb
    .text
test:
    # Jump to address 0. M-profile is Thumb-only, so the target carries the
    # Thumb bit; an even target would fault as a switch to ARM state instead
    # of as a fetch from NULL.
    mov r0, #1
    bx  r0
    nop
