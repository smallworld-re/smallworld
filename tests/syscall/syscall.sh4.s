    .text
test:
    ! Linux/SH puts the syscall number in r3 and the arguments in r4-r7, then
    ! r0 and r1.  Verified against QEMU's own Linux/SH user-mode entry,
    ! `linux-user/sh4/cpu_loop.c` case 0x160:
    !     do_syscall(env, env->gregs[3], env->gregs[4], env->gregs[5],
    !                env->gregs[6], env->gregs[7], env->gregs[0],
    !                env->gregs[1], 0, 0)
    ! `linux-user/sh4/syscall.tbl` gives write == 4.  The runner supplies r4-r6.
    !
    ! The number is set here rather than from Python on purpose: it makes the
    ! test cover the part of the machdef rewrite that has to *retain* the p-code
    ! ops preceding the trap.  Truncate one op too many and r3 is never written.
    mov     #4, r3

    ! SuperH's only trap instruction.  `SuperH4.sinc` lowers this to the
    ! `TrapAlways` userop, which angr sees as a CALLOTHER; `machdefs/superh4.py`
    ! rewrites that into an Ijk_Sys_syscall.  Under PANDA the same instruction is
    ! an interrupt (QEMU's 0x160), which is what tests/interrupt exercises.
    ! Linux/SH conventionally uses #0x10, but nothing checks the immediate --
    ! see the machdef comment.
    !
    ! This source is byte-identical to syscall.sh2a.s apart from these comments:
    ! `mov #imm,Rn` and `trapa #imm` are both base-SH encodings, so the two files
    ! exist only because SH-2A and SH-4 are separate sleigh specs that model
    ! `trapa` differently, not because the machine code differs.  sh4el reuses
    ! this source with -little.
    trapa   #0x10

    ! Where the syscall resumes: QEMU's dispatch does `env->pc += 2`, and the
    ! rewrite likewise sets the block's successor to trap + 2.  Landing here
    ! rather than on the exit point proves the resume address is right.
    nop
