import typing

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


def add_superh_core_registers(
    model: cpu.CPU, control_registers: typing.Sequence[str]
) -> None:
    """Add the general-purpose and control registers every SuperH shares.

    Arguments:
        model: The CPU model to add them to
        control_registers: The control registers, which must include `pr`
    """
    # *** General-Purpose Registers ***
    for i in range(0, 16):
        register = state.Register(f"r{i}", 4)
        setattr(model, f"r{i}", register)
        model.add(register)

    # *** Control Registers ***
    # Created before the aliases below, which reference `pr`.
    for name in control_registers:
        register = state.Register(name, 4)
        setattr(model, name, register)
        model.add(register)

    for alias, parent in SH2A_REGISTER_ALIASES.items():
        register = state.RegisterAlias(alias, getattr(model, parent), 4, 0)
        setattr(model, alias, register)
        model.add(register)


# Control registers of SH-1 and SH-2.
SH2_CONTROL_REGISTERS = (
    SH2A_PROGRAM_COUNTER_REGISTER,
    SH2A_STATUS_REGISTER,
    "pr",
    "gbr",
    "vbr",
    "mach",
    "macl",
)


class SH2AFPU(cpu.CPU):
    """CPU state model for SH-2A-FPU, big-endian."""

    platform = platforms.Platform(
        platforms.Architecture.SUPERH_SH2A_FPU, platforms.Byteorder.BIG
    )

    def __init__(self):
        super().__init__()

        # SH-2A adds the table base register to SH-2's control registers.
        add_superh_core_registers(self, SH2_CONTROL_REGISTERS + ("tbr",))

        # *** Floating-Point Registers ***
        add_superh_float_bank(self, "dr", "fr")

        for name in ("fpscr", "fpul"):
            register = state.Register(name, 4)
            setattr(self, name, register)
            self.add(register)


class SH2(cpu.CPU):
    """CPU state model for SH-2, big-endian. It has no FPU."""

    platform = platforms.Platform(
        platforms.Architecture.SUPERH_SH2, platforms.Byteorder.BIG
    )

    def __init__(self):
        super().__init__()
        add_superh_core_registers(self, SH2_CONTROL_REGISTERS)


class SH1(SH2):
    """CPU state model for SH-1, big-endian, which has SH-2's registers."""

    platform = platforms.Platform(
        platforms.Architecture.SUPERH_SH1, platforms.Byteorder.BIG
    )
