    .text
_start:
    ! SuperH's only synchronous trap instruction.  QEMU's helper_trapa() sets
    ! cs->exception_index = 0x160 unconditionally, which reaches PANDA's
    ! cb_before_handle_exception, so hook_interrupts() sees interrupt 352.
    !
    ! No SR preamble: trapa reads neither the T bit nor any SR field, and
    ! `ldc Rm,SR` is itself privileged, so writing SR would add a privilege
    ! dependency rather than remove one.  Measured start state on PANDA's
    ! sh7264 is SR = 0x400000f0, i.e. MD set (privileged), T clear, IMASK 0xf.
    trapa #0x10
