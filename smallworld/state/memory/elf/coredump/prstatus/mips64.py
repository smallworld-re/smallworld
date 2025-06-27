from ...... import platforms
from .prstatus import PrStatus


class MIPS64BE(PrStatus):
    architecture = platforms.Architecture.MIPS64
    byteorder = platforms.Byteorder.BIG

    # This doesn't match what the struct def says;
    # there's something extra in here.
    pr_regs_off = 112
    pr_regs_size = 360

    register_coords = [
        ("zero", 0x0, 8),
        ("at", 0x8, 8),
        ("v0", 0x10, 8),
        ("v1", 0x18, 8),
        ("a0", 0x20, 8),
        ("a1", 0x28, 8),
        ("a2", 0x30, 8),
        ("a3", 0x38, 8),
        ("a4", 0x40, 8),
        ("a5", 0x48, 8),
        ("a6", 0x50, 8),
        ("a7", 0x58, 8),
        ("t0", 0x60, 8),
        ("t1", 0x68, 8),
        ("t2", 0x70, 8),
        ("t3", 0x78, 8),
        ("s0", 0x80, 8),
        ("s1", 0x88, 8),
        ("s2", 0x90, 8),
        ("s3", 0x98, 8),
        ("s4", 0xA0, 8),
        ("s5", 0xA8, 8),
        ("s6", 0xB0, 8),
        ("s7", 0xB8, 8),
        ("t8", 0xC0, 8),
        ("t9", 0xC8, 8),
        ("k0", 0xD0, 8),
        ("k1", 0xD8, 8),
        ("gp", 0xE0, 8),
        ("sp", 0xE8, 8),
        ("s8", 0xF0, 8),
        ("ra", 0xF8, 8),
        # No idea what goes here.
        # There are exception pseudo-registers,
        # but they don't fit nicely in this gap.
        (None, 0x100, 8),
        (None, 0x108, 8),
        ("pc", 0x110, 8),
    ]


class MIPS64EL(MIPS64BE):
    byteorder = platforms.Byteorder.LITTLE
