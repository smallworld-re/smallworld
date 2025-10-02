    .text
_start:
    bl      foo
bar:
    li.d    $t1,8
    mul.d   $t1,$a0,$t1

    move    $t0,$a0
    move    $a0,$t1

    li.d    $t1,101
    blt     $t0,$t1,.L2
    li.d    $a0,32
.L2:
    ret
     
foo:
    addi.d  $sp,$sp,-48
    st.d    $fp,$sp,40
    addi.d  $fp,$sp,48
   
    addi.d  $a0,$a0,-1 
    bl      bar
    addi.d  $a0,$a0,1

    ld.d    $fp,$sp,40
    addi.d  $sp,$sp,48
   
    nop
