    .text
_start:
    bl      foo
bar:
    li.w    $t1,8
    mul.w   $t1,$a0,$t1

    move    $t0,$a0
    move    $a0,$t1

    li.w    $t1,101
    blt     $t0,$t1,.L2
    li.w    $a0,32
.L2:
    ret
     
foo:
    addi.w  $sp,$sp,-48
    st.w    $fp,$sp,40
    addi.w  $fp,$sp,48
   
    addi.w  $a0,$a0,-1 
    bl      bar
    addi.w  $a0,$a0,1

    ld.w    $fp,$sp,40
    addi.w  $sp,$sp,48
   
