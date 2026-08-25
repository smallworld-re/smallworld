from ... import platforms, state
from ...platforms.defs.superh import (
    SH2A_PROGRAM_COUNTER_REGISTER,
    SH2A_REGISTER_ALIASES,
    SH2A_STATUS_REGISTER,
)
from . import cpu


def add_superh_float_bank(
    model: cpu.CPU, double_prefix: str, single_prefix: str
) -> None:
    """Add one SuperH floating-point bank to a CPU model.

    Mirrors ``platforms.defs.superh.float_bank_registers``: the 8-byte
    double-precision register is the parent, and ``DRn = FRn:FRn+1`` with FRn as
    the upper half, so the even-numbered single-precision register is at numeric
    offset 4 and the odd-numbered one at 0. See that function for the caveat
    about SH-4's alternate (``xf``/``xd``) bank on little-endian sleigh.
    """
    for i in range(0, 16, 2):
        double = state.Register(f"{double_prefix}{i}", 8)
        setattr(model, f"{double_prefix}{i}", double)
        model.add(double)

        for name, offset in (
            (f"{single_prefix}{i}", 4),
            (f"{single_prefix}{i + 1}", 0),
        ):
            single = state.RegisterAlias(name, double, 4, offset)
            setattr(model, name, single)
            model.add(single)


class SH2AFPU(cpu.CPU):
    """CPU state model for SH-2A-FPU, big-endian."""

    platform = platforms.Platform(
        platforms.Architecture.SUPERH_SH2A_FPU, platforms.Byteorder.BIG
    )

    def __init__(self):
        super().__init__()

        # *** General-Purpose Registers ***
        for i in range(0, 16):
            register = state.Register(f"r{i}", 4)
            setattr(self, f"r{i}", register)
            self.add(register)

        # *** Control Registers ***
        # Created before the aliases below, which reference `pr`.
        for name in (
            SH2A_PROGRAM_COUNTER_REGISTER,
            SH2A_STATUS_REGISTER,
            "pr",
            "gbr",
            "vbr",
            "tbr",
            "mach",
            "macl",
        ):
            register = state.Register(name, 4)
            setattr(self, name, register)
            self.add(register)

        for alias, parent in SH2A_REGISTER_ALIASES.items():
            register = state.RegisterAlias(alias, getattr(self, parent), 4, 0)
            setattr(self, alias, register)
            self.add(register)

        # *** Floating-Point Registers ***
        add_superh_float_bank(self, "dr", "fr")

        for name in ("fpscr", "fpul"):
            register = state.Register(name, 4)
            setattr(self, name, register)
            self.add(register)
