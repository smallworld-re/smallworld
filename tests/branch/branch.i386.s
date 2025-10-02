    .text
# This function returns 1 if arg1 is 100, and 0 otherwise
    xor     %eax,%eax
    cmp     $100,%edi
    sete    %al
    nop
