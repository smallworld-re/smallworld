# This is a function that just squares a number.
# It takes a 16-bit argument in di and returns the 16-bit product in ax.
# If we can't run this, we can't run anything.
    .code16
    .text
square:
    imul    %di, %di
    mov     %di, %ax
