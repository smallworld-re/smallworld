from ...... import platforms
from .prstatus import PrStatus


class I386(PrStatus):
    architecture = platforms.Architecture.X86_32
    byteorder = platforms.Byteorder.LITTLE

    pr_regs_off = 72
    pr_regs_size = 68

    # The kernel stores each segment selector in a 4-byte slot, but the value
    # is a 2-byte selector in the low bytes, and the CPU segment registers are
    # 2 bytes wide (state.Register("cs", 2), ...). Read 2 bytes so the parsed
    # value fits the register instead of pulling in the high padding.
    register_coords = [
        ("ebx", 0x0, 4),
        ("ecx", 0x4, 4),
        ("edx", 0x8, 4),
        ("esi", 0xC, 4),
        ("edi", 0x10, 4),
        ("ebp", 0x14, 4),
        ("eax", 0x18, 4),
        ("ds", 0x1C, 2),
        ("es", 0x20, 2),
        ("fs", 0x24, 2),
        ("gs", 0x28, 2),
        (None, 0x2C, 4),  # orig_eax
        ("eip", 0x30, 4),
        ("cs", 0x34, 2),
        ("eflags", 0x38, 4),
        ("esp", 0x3C, 4),
        ("ss", 0x40, 2),
    ]
