    # Calls between standard MIPS32 and microMIPS code, in every direction a
    # program switches:
    #   - jalx from MIPS32 to microMIPS;
    #   - jalr from microMIPS through a function pointer to MIPS32 code;
    #   - jalr from MIPS32 through a function pointer whose low bit marks a
    #     microMIPS function;
    #   - jr ra back across the switch, both ways.
    #
    # microMIPS code takes MIPS32 addresses in registers rather than calling
    # them with jalx or loading them with la: LLVM relocates those with the
    # standard MIPS relocations, which patch a 32-bit word in memory order,
    # and that scrambles a little-endian microMIPS instruction (two
    # halfwords, high halfword first).
    # With a0 = n on entry, the result in v0 is (n + 1) * 2 + 3.
    .text
    .set    noreorder
    .set    nomacro
    .set    nomips16

    .set    nomicromips
    .globl  __start
    .ent    __start
    .type   __start, @function
__start:
    move    $s0,$ra
    la      $t8,mips_double
    # MIPS32 -> microMIPS by jalx: v0 = (a0 + 1) * 2
    jalx    micro_inc
    nop
    # MIPS32 -> microMIPS through a function pointer: v0 += 3
    move    $a0,$v0
    la      $t9,micro_add3
    jalr    $t9
    nop
    jr      $s0
    nop
    .end    __start
    .size   __start, .-__start

    .globl  mips_double
    .ent    mips_double
    .type   mips_double, @function
mips_double:
    # Called from microMIPS: ra has its low bit set, so jr returns there.
    jr      $ra
    addu    $v0,$a0,$a0
    .end    mips_double
    .size   mips_double, .-mips_double

    .set    micromips
    .globl  micro_inc
    .ent    micro_inc
    .type   micro_inc, @function
micro_inc:
    addiu   $sp,$sp,-8
    sw      $ra,4($sp)
    addiu   $a0,$a0,1
    # microMIPS -> MIPS32 through the pointer in t8, whose low bit is clear
    jalr    $t8
    nop
    lw      $ra,4($sp)
    addiu   $sp,$sp,8
    # Called from MIPS32: ra is even, so jr returns to MIPS32.
    jr      $ra
    nop
    .end    micro_inc
    .size   micro_inc, .-micro_inc

    .globl  micro_add3
    .ent    micro_add3
    .type   micro_add3, @function
micro_add3:
    jr      $ra
    addiu   $v0,$a0,3
    .end    micro_add3
    .size   micro_add3, .-micro_add3
