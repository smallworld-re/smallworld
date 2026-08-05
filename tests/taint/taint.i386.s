# Dynamic taint-tracking exercise (i386, AT&T syntax).
#
# Inputs (set by the harness):
#   edi = taint source "a"
#   esi = taint source "b"
#   ebx = pointer to an 8-byte scratch buffer (taint source "ptr")
#   edx = taint source "clearme"
#
# Exercises register->register copy, arithmetic taint union, register->memory
# store, memory->register load, and a taint-clearing idiom.
    .text
    mov     %edi, %eax      # eax <- a
    add     %esi, %eax      # eax <- a + b
    mov     %eax, (%ebx)    # store a | b to the buffer
    mov     (%ebx), %ecx    # load it back into ecx
    xor     %edx, %edx      # clears edx's taint
