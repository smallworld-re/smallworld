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

    ! SuperH's only trap instruction.  Under angr this is rewritten into an
    ! Ijk_Sys_syscall by `machdefs/superh.py`; under PANDA the same instruction
    ! is an interrupt (QEMU's 0x160), which is what tests/interrupt exercises.
    ! Linux/SH conventionally uses #0x10, but nothing checks the immediate --
    ! see the machdef comment.
    !
    ! No `ldc ..., sr` preamble is needed even though this is SH-2A: neither
    ! `mov #imm,Rn` nor `trapa` reads the T bit, and the rewrite truncates the
    ! block before sleigh's `*r15 = sr` push ever executes, so angr's
    ! unconstrained `sr` cannot leak into the result.
    trapa   #0x10

    ! Where the syscall resumes: QEMU's dispatch does `env->pc += 2`, and the
    ! rewrite likewise sets the block's successor to trap + 2.  Landing here
    ! rather than on the exit point proves the resume address is right.
    nop
