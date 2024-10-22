    .text
    .align  2
    .globl  __start
    .set    nomips16
    .set    nomicromips
    .ent    __start
    .type   __start, @function
__start:
    .set    noreorder
    .set    nomacro

    # Load argc
    lw      $t0,($sp)
    
    # If argc != 2, exit
    li      $t1, 2
    bne     $t0,$t1,.L2
    nop                     # Delay slot

    # Load argv
    lw      $t0,4($sp)
    # Load argv[1]
    lw      $t0,4($t0)

    li      $v0, 0

.L3:
    # for(i = 0; argv[1][i] != '\0'; i++);
    addu    $t1,$t0,$v0
    lb      $t1,($t1)
    beq     $t1,$0,.L1 
    nop                     # Delay slot
    addiu   $v0,$v0,1
    b       .L3
    nop                     # Delay slot

.L2:
    # Failed; return -1
    li      $v0, -1

.L1:
    jr      $ra
    nop                     # Delay slot

    .set    macro
    .set    reorder
    .end    __start
    .size   __start, .-__start
