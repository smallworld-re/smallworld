    .text
    .set noreorder
    .set nomacro
# Fake the PLT
foobar:
    break
test:
    daddiu  $sp,$sp,-48
    sd      $ra,40($sp)
    sd      $fp,32($sp)
    sd      $gp,24($sp)
    move    $fp,$sp

    # int *ret = foobar();
    bal     foobar
    nop

    # return *ret;
    lw      $v0,0($v0)
    
    # Clean up the stack
    move    $sp,$fp
    ld      $ra,40($sp)
    ld      $fp,32($sp)
    ld      $gp,24($sp)
    daddiu  $sp,$sp,48
    nop 
