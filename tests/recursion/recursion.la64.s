    .text
_start:
    bl      main

mc91:
    # Set up the stack frame
    addi.d  $sp,$sp,-48
    st.d    $ra,$sp,40
    st.d    $fp,$sp,32
    addi.d  $fp,$sp,48

    # Check if we want case one or case two
    li.w    $t0,100
    ble     $a0,$t0,.L2

    # Case 1: n > 100 -> M(n) := n - 10
    addi.w  $a0,$a0,-10
    b       .L3

.L2:
    # Case 2: n <= 100 -> M(n) := M(M(n + 11))
    addi.w  $a0,$a0,11
    bl      mc91
    bl      mc91
.L3:
    # Clean up the stack and return
    ld.d    $fp,$sp,32
    ld.d    $ra,$sp,40
    addi.d  $sp,$sp,48
    ret

main:
    bl      mc91
