    .code16
    .text
# This function returns 1 if arg1 is 100, and 0 otherwise
    xor     %ax,%ax
    cmp     $100,%di
    sete    %al
