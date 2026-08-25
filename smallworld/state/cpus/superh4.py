from ... import platforms, state
from ...platforms.defs.superh4 import (
    SH4_PROGRAM_COUNTER_REGISTER,
    SH4_REGISTER_ALIASES,
    SH4_STATUS_REGISTER,
)
from . import cpu
from .superh import add_superh_float_bank


class SuperH4(cpu.CPU):
    """Shared SH-4/SH-4A CPU state model.

    Deliberately has no ``platform``, so ``find_subclass`` never selects it; the
    concrete per-endianness subclasses below do. Mirrors
    ``platforms.defs.superh4.SuperH4Def`` exactly - ``tests/unit.py``'s CPUTests
    asserts set equality between the two.
    """

    def __init__(self):
        super().__init__()

        # *** General-Purpose Registers ***
        for i in range(0, 16):
            register = state.Register(f"r{i}", 4)
            setattr(self, f"r{i}", register)
            self.add(register)

        # *** Banked Registers ***
        for i in range(0, 8):
            register = state.Register(f"r{i}_bank", 4)
            setattr(self, f"r{i}_bank", register)
            self.add(register)

        # *** Control Registers ***
        # Created before the aliases below, which reference `pr`.
        for name in (
            SH4_PROGRAM_COUNTER_REGISTER,
            SH4_STATUS_REGISTER,
            "pr",
            "gbr",
            "vbr",
            "ssr",
            "spc",
            "sgr",
            "dbr",
            "mach",
            "macl",
        ):
            register = state.Register(name, 4)
            setattr(self, name, register)
            self.add(register)

        for alias, parent in SH4_REGISTER_ALIASES.items():
            register = state.RegisterAlias(alias, getattr(self, parent), 4, 0)
            setattr(self, alias, register)
            self.add(register)

        # *** Floating-Point Registers ***
        # Two banks, swapped by `frchg`.
        add_superh_float_bank(self, "dr", "fr")
        add_superh_float_bank(self, "xd", "xf")

        for name in ("fpscr", "fpul"):
            register = state.Register(name, 4)
            setattr(self, name, register)
            self.add(register)


class SuperH4BE(SuperH4):
    """CPU state model for SH-4/SH-4A, big-endian."""

    platform = platforms.Platform(
        platforms.Architecture.SUPERH_SH4, platforms.Byteorder.BIG
    )


class SuperH4EL(SuperH4):
    """CPU state model for SH-4/SH-4A, little-endian."""

    platform = platforms.Platform(
        platforms.Architecture.SUPERH_SH4, platforms.Byteorder.LITTLE
    )
