    .text
foobar:
    break 0
test:
    addi.d  $sp,$sp,-48
    st.d    $ra,$sp,40
    st.d    $fp,$sp,32
    addi.d  $fp,$sp,48
    
    # int *ret = foobar();
    bl      foobar

    # return *ret
    ld.w    $a0,$a0,0

    # Clean up the stack
    ld.d    $ra,$sp,40
    ld.d    $fp,$sp,32
    addi.d  $sp,$sp,48
