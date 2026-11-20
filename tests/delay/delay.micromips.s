    .text
    .set    noreorder
    .set    nomacro
    .set    nomips16
    .set    micromips
test:
    # Tests single-stepping delay slot instructions
    # If the branches are not taken correctly,
    # the return value will be incorrect.
    #
    # The branches are microMIPS's 16-bit forms, with 16-bit delay-slot
    # instructions, and a compact branch, which has no delay slot: the
    # instruction after it must run on its own. MIPS32's delay test covers
    # the 32-bit branches microMIPS shares with it.

    # Set a flag so I can use a conditional jump
    addiu   $a0,$zero,1

    # Set an address so I can dereference
    addiu   $a1,$zero,0x2000

    addiu   $v0,$zero,1
    b16     .L1
    sw16    $v0,0($a1)

    # Dead block
    addiu   $v0,$zero,-1
    sw16    $v0,0($a1)

.L1:
    addiu   $v0,$v0,1
    # beqz16 $a0,.L2, encoded by hand: zig's toolchain writes beqz16's
    # branch offset into the halfword after it, corrupting the delay slot.
    .hword  0x8e07
    sw16    $v0,0($a1)

    # Never taken; the b16 after it is not its delay slot.
    beqzc   $a1,.L2
    b16     .L1
    li16    $a0,0

    # Dead block
    addiu   $v0,$zero,-1

.L2:
    addiu   $v0,$v0,1
    sw16    $v0,0($a1)
