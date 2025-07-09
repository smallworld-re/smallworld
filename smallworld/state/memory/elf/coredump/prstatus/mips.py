from ...... import platforms
from .prstatus import PrStatus


class MIPS32BE(PrStatus):
    architecture = platforms.Architecture.MIPS32
    byteorder = platforms.Byteorder.BIG

    # This doesn't match what the struct def says;
    # there's something extra in here.
    pr_regs_off = 96
    pr_regs_size = 180

    register_coords = [
        ("zero", 0x0, 4),
        ("at", 0x4, 4),
        ("v0", 0x8, 4),
        ("v1", 0xC, 4),
        ("a0", 0x10, 4),
        ("a1", 0x14, 4),
        ("a2", 0x18, 4),
        ("a3", 0x1C, 4),
        ("t0", 0x20, 4),
        ("t1", 0x24, 4),
        ("t2", 0x28, 4),
        ("t3", 0x2C, 4),
        ("t4", 0x30, 4),
        ("t5", 0x34, 4),
        ("t6", 0x38, 4),
        ("t7", 0x3C, 4),
        ("s0", 0x40, 4),
        ("s1", 0x44, 4),
        ("s2", 0x48, 4),
        ("s3", 0x4C, 4),
        ("s4", 0x50, 4),
        ("s5", 0x54, 4),
        ("s6", 0x58, 4),
        ("s7", 0x5C, 4),
        ("t8", 0x60, 4),
        ("t9", 0x64, 4),
        ("k0", 0x68, 4),
        ("k1", 0x6C, 4),
        ("gp", 0x70, 4),
        ("sp", 0x74, 4),
        ("s8", 0x78, 4),
        ("ra", 0x7C, 4),
        # No idea what goes here.
        # There are exception pseudo-registers,
        # but they don't fit nicely in this gap.
        ("pc", 0x88, 4),
    ]


class MIPS32EL(MIPS32BE):
    byteorder = platforms.Byteorder.LITTLE
