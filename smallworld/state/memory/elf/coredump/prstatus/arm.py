from ...... import platforms
from .prstatus import PrStatus


class ARM(PrStatus):
    byteorder = platforms.Byteorder.LITTLE

    pr_regs_off = 72
    pr_regs_size = 72

    register_coords = [
        ("r0", 0x0, 4),
        ("r1", 0x4, 4),
        ("r2", 0x8, 4),
        ("r3", 0xC, 4),
        ("r4", 0x10, 4),
        ("r5", 0x14, 4),
        ("r6", 0x18, 4),
        ("r7", 0x1C, 4),
        ("r8", 0x20, 4),
        ("r9", 0x24, 4),
        ("r10", 0x28, 4),
        ("r11", 0x2C, 4),
        ("r12", 0x30, 4),
        ("sp", 0x34, 4),
        ("lr", 0x38, 4),
        ("pc", 0x3C, 4),
        # TODO: This is missing two registers.  One is the CPSR, but I have no idea which.
    ]


class ARMv5T(ARM):
    architecture = platforms.Architecture.ARM_V5T


class ARMv6M(ARM):
    architecture = platforms.Architecture.ARM_V6M


class ARMv6MThumb(ARM):
    architecture = platforms.Architecture.ARM_V6M_THUMB


class ARMv7M(ARM):
    architecture = platforms.Architecture.ARM_V7M


class ARMv7R(ARM):
    architecture = platforms.Architecture.ARM_V7R


class ARMv7A(ARM):
    architecture = platforms.Architecture.ARM_V7A
