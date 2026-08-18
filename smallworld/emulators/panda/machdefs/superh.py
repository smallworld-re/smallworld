import typing

from ....platforms import Architecture, Byteorder
from ....platforms.defs.superh import (
    SH2A_PROGRAM_COUNTER_REGISTER,
    SH2A_REGISTER_ALIASES,
    SH2A_STATUS_REGISTER,
)
from .machdef import PandaMachineDef

# QEMU upstream has no SH-2A CPU model at all - its `sh4` target only ships
# SH-4 models (sh7750r, sh7751r, sh7785). `sh7264` is added by
# `nix/patches/panda-qemu-sh2a.patch`, along with the SH-2A ISA itself: the
# SH-2A-only instructions, the 32-bit instruction forms, and the TBR register.
# SH7264 and SH7269 are real SH2A-FPU parts and share the core.
#
# See `nix/patches/README.panda-qemu-sh2a.md` for what that patch does and does
# not implement; the notable gap is the register-bank instructions
# (`ldbank`/`stbank`/`resbank`), which decode but raise illegal-instruction.
SH2A_PANDA_CPU = "sh7264"


class SH2AFPUMachineDef(PandaMachineDef):
    """SH-2A-FPU on PANDA, big-endian.

    Runs on the `sh4eb` target, because SH-2A shares QEMU's SuperH translator
    with SH-4 and our SH-2A CPU model is big-endian - the only endianness
    Ghidra, pypcode and Styx model SH-2A in, so the one SmallWorld exposes.

    As with the SH-4 machdefs there is deliberately no `machine` attribute, so
    PandaEmulator uses `-M configurable`: a bare CPU with no peripherals, which
    lets SmallWorld map its own memory rather than working around a board's
    fixed layout.
    """

    arch = Architecture.SUPERH_SH2A_FPU
    byteorder = Byteorder.BIG

    panda_arch = "sh4eb"
    cpu = SH2A_PANDA_CPU

    _registers: typing.Dict[str, typing.Optional[str]] = {
        **{f"r{i}": f"r{i}" for i in range(0, 16)},
        **SH2A_REGISTER_ALIASES,
        SH2A_PROGRAM_COUNTER_REGISTER: SH2A_PROGRAM_COUNTER_REGISTER,
        SH2A_STATUS_REGISTER: SH2A_STATUS_REGISTER,
        # `tbr` is SH-2A-only and is added to CPUSH4State by our patch; it backs
        # `jsr/n @@(disp,tbr)`.
        **{name: name for name in ("pr", "gbr", "vbr", "tbr", "mach", "macl")},
        # SH-2A has a single floating-point bank, unlike SH-4's fr/xf pair.
        **{f"fr{i}": f"fr{i}" for i in range(0, 16)},
        **{f"dr{i}": f"dr{i}" for i in range(0, 16, 2)},
        "fpscr": "fpscr",
        "fpul": "fpul",
    }
