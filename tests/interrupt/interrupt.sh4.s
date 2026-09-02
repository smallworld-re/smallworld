    .text
_start:
    ! SuperH's only synchronous trap instruction.  QEMU's helper_trapa() sets
    ! cs->exception_index = 0x160 unconditionally, which reaches PANDA's
    ! cb_before_handle_exception, so hook_interrupts() sees interrupt 352.
    ! `case 0xc300` in target/sh4/translate.c carries no CHECK_PRIVILEGED, so
    ! this holds in user mode too.
    !
    ! No SR preamble: trapa reads neither the T bit nor any SR field, and
    ! `ldc Rm,SR` is both privileged and would flip SR.RB, re-banking r0-r7.
    ! Measured start state on PANDA's sh7751r is SR = 0x700000f0, QEMU's SH-4
    ! reset value: MD | RB | BL with IMASK 0xf.
    trapa #0x10
