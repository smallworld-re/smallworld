    .text
foobar:
    break 0
test:
    addi.w  $sp,$sp,-48
    st.w    $ra,$sp,40
    st.w    $fp,$sp,32
    addi.w  $fp,$sp,48
    
    # int *ret = foobar();
    bl      foobar

    # return *ret
    ld.w    $a0,$a0,0

    # Clean up the stack
    ld.w    $ra,$sp,40
    ld.w    $fp,$sp,32
    addi.w  $sp,$sp,48
