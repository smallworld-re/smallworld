    .text
manyargs:
    # Take seven args
    # add 1, 3, 5, 7
    # return the sum
    l32i    $a3, $sp, 0
    add     $a2, $a2, $a4
    add     $a2, $a2, $a6
    add     $a2, $a2, $a3
    
