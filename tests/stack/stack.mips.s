    .text
    .set noreorder
    .set nomacro
manyargs:
    # Add arg1 ($4) and arg2 ($6)
    # Store result in return register ($2)
    addu $2,$4,$6
    # Load arg5 (sp+16), add to result
    lw $3,16($sp)
    addu $2,$2,$3
    # Load arg7 (sp+24), add to result
    lw $3,24($sp)
    addu $2,$2,$3
    nop
