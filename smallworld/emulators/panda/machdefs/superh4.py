import typing

from ....platforms import Architecture, Byteorder
from ....platforms.defs.superh4 import (
    SH4_PROGRAM_COUNTER_REGISTER,
    SH4_REGISTER_ALIASES,
    SH4_STATUS_REGISTER,
)
from .machdef import PandaMachineDef

# QEMU's `sh4` target only ships SH-4 CPU models: sh7750r, sh7751r and sh7785.
# SH7751R is the middle-of-the-road SH-4 with the fewest board assumptions, and
# it is also what the Avatar `configurable` machine defaults to.
SH4_PANDA_CPU = "sh7751r"

# Registers PANDA can reach through pandare2's SuperHArch, which reads
# CPUSH4State directly. Everything in the SmallWorld platform definition is
# covered; nothing needs to be `None`, because QEMU models the whole SH-4
# register file including both the GPR and floating-point alternate banks.
_SUPERH4_REGISTERS: typing.Dict[str, typing.Optional[str]] = {
    **{f"r{i}": f"r{i}" for i in range(0, 16)},
    **{f"r{i}_bank": f"r{i}_bank" for i in range(0, 8)},
    **SH4_REGISTER_ALIASES,
    SH4_PROGRAM_COUNTER_REGISTER: SH4_PROGRAM_COUNTER_REGISTER,
    SH4_STATUS_REGISTER: SH4_STATUS_REGISTER,
    **{
        name: name
        for name in ("pr", "gbr", "vbr", "ssr", "spc", "sgr", "dbr", "mach", "macl")
    },
    # Floating point. `fr`/`dr` are the primary bank, `xf`/`xd` the alternate one
    # that `frchg` swaps in; QEMU keeps both in `fregs[32]`.
    **{f"fr{i}": f"fr{i}" for i in range(0, 16)},
    **{f"xf{i}": f"xf{i}" for i in range(0, 16)},
    **{f"dr{i}": f"dr{i}" for i in range(0, 16, 2)},
    **{f"xd{i}": f"xd{i}" for i in range(0, 16, 2)},
    "fpscr": "fpscr",
    "fpul": "fpul",
}


class SuperH4BEMachineDef(PandaMachineDef):
    """SH-4/SH-4A on PANDA, big-endian.

    Note the absence of a `machine` attribute: PandaEmulator falls back to
    `-M configurable`, the Avatar machine, which builds a bare CPU with no
    peripherals and lets SmallWorld map its own memory. QEMU's only real SH-4
    board is `r2d`, whose fixed SDRAM window at 0x0c000000 would constrain where
    harnesses could place code.
    """

    arch = Architecture.SUPERH_SH4
    byteorder = Byteorder.BIG

    panda_arch = "sh4eb"
    cpu = SH4_PANDA_CPU
    _registers = _SUPERH4_REGISTERS


class SuperH4ELMachineDef(SuperH4BEMachineDef):
    """SH-4/SH-4A on PANDA, little-endian."""

    byteorder = Byteorder.LITTLE

    panda_arch = "sh4"
