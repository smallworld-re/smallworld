    .text
    .set    micromips
test:
    li      $v0,4004
    syscall
    nop
