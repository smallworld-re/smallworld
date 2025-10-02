    .text
    .set noreorder
    .set nomacro
# Fake the PLT
foobar:
    break
test:
    # Set up the stack
    addiu   $sp,$sp,-32
    sw      $ra,28($sp)
    sw      $fp,24($sp)
    move    $fp,$sp

    # int *ret = foobar();
    bal     foobar
    nop
    
    # return *ret
    lw      $v0,0($v0)

    # Clean up the stack
    move    $sp,$fp
    lw      $ra,28($sp)
    lw      $fp,24($sp)
    addiu   $sp,$sp,32
    nop 
