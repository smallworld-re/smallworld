# This is a function that just squares a number. 
# It takes a 32-bit argument in edi and returns the 32-bit product in eax.
# If we can't run this, we can't run anything.
    .text
square:
    imul    %edi, %edi
    mov     %edi, %eax
