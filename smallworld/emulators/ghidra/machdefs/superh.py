import typing

from ....platforms import Architecture, Byteorder
from ....platforms.defs.superh import (
    SH2A_PROGRAM_COUNTER_REGISTER,
    SH2A_REGISTER_ALIASES,
    SH2A_STATUS_REGISTER,
)
from .machdef import GhidraMachineDef

# Control and system registers, in Ghidra's spelling. SH-2A's sleigh spec
# (`Processors/SuperH/data/languages/superh.sinc`) names everything lowercase, so
# this is an identity map. SuperH4's spec does not - see `superh4.py` - and
# keeping the same shape in both files makes that difference obvious.
SH2A_CONTROL_REGISTERS = (
    SH2A_PROGRAM_COUNTER_REGISTER,
    SH2A_STATUS_REGISTER,
    "pr",
    "gbr",
    "vbr",
    "tbr",
    "mach",
    "macl",
)


class SH2AFPUMachineDef(GhidraMachineDef):
    arch = Architecture.SUPERH_SH2A_FPU
    byteorder = Byteorder.BIG

    # Ghidra folds a SuperH delay slot into the translation of the branch that
    # owns it, so one "step" covers both instructions and is safe. Compare
    # `ghidra/machdefs/mips.py`, which sets this for the same reason.
    supports_single_step = True

    _registers: typing.Dict[str, typing.Optional[str]] = {
        # *** General-Purpose Registers ***
        **{f"r{i}": f"r{i}" for i in range(0, 16)},
        # Sleigh has no `sp`/`fp`/`ra`/`lr`, so each alias resolves to the
        # architectural register it names.
        **SH2A_REGISTER_ALIASES,
        # *** Control Registers ***
        **{name: name for name in SH2A_CONTROL_REGISTERS},
        # *** Floating-Point Registers ***
        **{f"dr{i}": f"dr{i}" for i in range(0, 16, 2)},
        **{f"fr{i}": f"fr{i}" for i in range(0, 16)},
        "fpscr": "fpscr",
        "fpul": "fpul",
        # NOTE: the sleigh spec also defines `resbank_base`, a 40 KiB pseudo
        # register covering SH-2A's 512 register banks. It is deliberately absent
        # from the platform definition, so there is nothing to map here.
    }
