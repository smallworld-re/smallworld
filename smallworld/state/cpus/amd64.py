from ... import platforms
from .. import state
from . import i386
from ...arch import amd64_arch

class AMD64(i386.I386):
    """AMD64 CPU state model."""

    _GENERAL_PURPOSE_REGS = [
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rdi",
        "rsi",
        "rbp",
        "rsp",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
    ]

    platform = platforms.Platform(
        platforms.Architecture.X86_64, platforms.Byteorder.LITTLE
    )

    arch_info = amd64_arch.info

    # this should be unnecessary (?) when i386 cpu has been implemented.
    def __init__(self):
        # use arch_info to create all these regs and reg aliases...
        super(i386.I386, self).__init__()

        
