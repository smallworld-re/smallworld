from ...... import platforms
from .prstatus import PrStatus


class AMD64(PrStatus):
    architecture = platforms.Architecture.X86_64
    byteorder = platforms.Byteorder.LITTLE

    pr_regs_off = 112
    pr_regs_size = 216

    register_coords = [
        ("r15", 0x0, 8),
        ("r14", 0x8, 8),
        ("r13", 0x10, 8),
        ("r12", 0x18, 8),
        ("rbp", 0x20, 8),
        ("rbx", 0x28, 8),
        ("r11", 0x30, 8),
        ("r10", 0x38, 8),
        ("r9", 0x40, 8),
        ("r8", 0x48, 8),
        ("rax", 0x50, 8),
        ("rcx", 0x58, 8),
        ("rdx", 0x60, 8),
        ("rsi", 0x68, 8),
        ("rdi", 0x70, 8),
        (None, 0x78, 8),  # orig_rax
        ("rip", 0x80, 8),
        ("cs", 0x88, 8),
        ("eflags", 0x90, 8),
        ("rsp", 0x98, 8),
        ("ss", 0xA0, 8),
        (None, 0xA8, 8),  # fs_base
        (None, 0xB0, 8),  # gs_base
        ("ds", 0xB8, 8),
        ("es", 0xC0, 8),
        ("fs", 0xC8, 8),
        ("gs", 0xD0, 8),
    ]
