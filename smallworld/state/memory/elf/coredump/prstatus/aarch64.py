from ...... import platforms
from .prstatus import PrStatus


class AArch64(PrStatus):
    architecture = platforms.Architecture.AARCH64
    byteorder = platforms.Byteorder.LITTLE

    pr_regs_off = 112
    pr_regs_size = 272

    register_coords = [
        ("x0", 0x0, 8),
        ("x1", 0x8, 8),
        ("x2", 0x10, 8),
        ("x3", 0x18, 8),
        ("x4", 0x20, 8),
        ("x5", 0x28, 8),
        ("x6", 0x30, 8),
        ("x7", 0x38, 8),
        ("x8", 0x40, 8),
        ("x9", 0x48, 8),
        ("x10", 0x50, 8),
        ("x11", 0x58, 8),
        ("x12", 0x60, 8),
        ("x13", 0x68, 8),
        ("x14", 0x70, 8),
        ("x15", 0x78, 8),
        ("x16", 0x80, 8),
        ("x17", 0x88, 8),
        ("x18", 0x90, 8),
        ("x19", 0x98, 8),
        ("x20", 0xA0, 8),
        ("x21", 0xA8, 8),
        ("x22", 0xB0, 8),
        ("x23", 0xB8, 8),
        ("x24", 0xC0, 8),
        ("x25", 0xC8, 8),
        ("x26", 0xD0, 8),
        ("x27", 0xD8, 8),
        ("x28", 0xE0, 8),
        ("x29", 0xE8, 8),
        ("x30", 0xF0, 8),
        ("sp", 0xF8, 8),
        ("pc", 0x100, 8),
    ]
