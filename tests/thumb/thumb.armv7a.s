    .text
test:
    mov r1, #1
    add r0, r1
    add r0, #1
    blx thumb

    .thumb
thumb:
    mov r1, #1
    add r0, r1
    add r0, #1
    blx arm

    .arm
arm:
    mov r1, #1
    add r0, r1
    add r0, #1
    nop
