    .syntax unified
    .thumb
    .text
square:
    # Square the first argument (r0)
    # and save it to the return (r0)
    mul r0, r0, r0
