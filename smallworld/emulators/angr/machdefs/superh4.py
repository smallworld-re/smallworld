import typing

import angr
import archinfo

from ....platforms import Architecture, Byteorder
from ....platforms.defs.superh4 import (
    SH4_FLOAT_ARGUMENT_REGISTERS,
    SH4_INTEGER_ARGUMENT_REGISTERS,
    SH4_PROGRAM_COUNTER_REGISTER,
    SH4_REGISTER_ALIASES,
    SH4_RETURN_ADDRESS_REGISTER,
    SH4_RETURN_VALUE_REGISTER,
    SH4_STATUS_REGISTER,
)
from .machdef import GhidraMachineDef

SH4_BE_PCODE_LANGUAGE = "SuperH4:BE:32:default"
SH4_EL_PCODE_LANGUAGE = "SuperH4:LE:32:default"


class SuperH4MachineDef(GhidraMachineDef):
    """Shared SH-4/SH-4A definition.

    Has no ``byteorder`` or ``pcode_language``, so ``find_subclass`` never
    selects it; the concrete subclasses below do.
    """

    arch = Architecture.SUPERH_SH4

    # As on SH-2A: sleigh lifts a branch together with its delay slot.
    supports_single_step = True

    # `archinfo.ArchPcode` lowercases every sleigh register name, so even though
    # SuperH4's spec spells the banked, control and system registers in uppercase
    # (R0_BANK, GBR, PC, MACH, FPSCR, ...) this map is lowercase throughout -
    # unlike the Ghidra machdef, which talks to sleigh directly and must preserve
    # the original case.
    _registers: typing.Dict[str, str] = {
        # *** General-Purpose Registers ***
        **{f"r{i}": f"r{i}" for i in range(0, 16)},
        # ArchPcode synthesizes `sp` and `ip`, but not `fp`/`ra`/`lr`.
        **SH4_REGISTER_ALIASES,
        # *** Banked Registers ***
        **{f"r{i}_bank": f"r{i}_bank" for i in range(0, 8)},
        # *** Control Registers ***
        SH4_PROGRAM_COUNTER_REGISTER: SH4_PROGRAM_COUNTER_REGISTER,
        SH4_STATUS_REGISTER: SH4_STATUS_REGISTER,
        "pr": "pr",
        "gbr": "gbr",
        "vbr": "vbr",
        "ssr": "ssr",
        "spc": "spc",
        "sgr": "sgr",
        "dbr": "dbr",
        "mach": "mach",
        "macl": "macl",
        # *** Floating-Point Registers ***
        **{f"dr{i}": f"dr{i}" for i in range(0, 16, 2)},
        **{f"fr{i}": f"fr{i}" for i in range(0, 16)},
        **{f"xd{i}": f"xd{i}" for i in range(0, 16, 2)},
        **{f"xf{i}": f"xf{i}" for i in range(0, 16)},
        "fpscr": "fpscr",
        "fpul": "fpul",
    }


class SuperH4BEMachineDef(SuperH4MachineDef):
    byteorder = Byteorder.BIG
    pcode_language = SH4_BE_PCODE_LANGUAGE


class SuperH4ELMachineDef(SuperH4MachineDef):
    byteorder = Byteorder.LITTLE
    pcode_language = SH4_EL_PCODE_LANGUAGE


class SimCCSuperH4(angr.calling_conventions.SimCC):
    """SH-4 calling convention, per ``SuperH4_{be,le}.cspec``.

    SH-4 passes twice as many floating-point arguments as SH-2A (fr4-fr11), and
    additionally names dr4/dr6/dr8/dr10 for double-precision arguments. SimCC has
    no separate double-argument list, so only the single-precision registers are
    declared; the doubles overlay the same register file.
    """

    ARG_REGS = list(SH4_INTEGER_ARGUMENT_REGISTERS)
    FP_ARG_REGS = list(SH4_FLOAT_ARGUMENT_REGISTERS)
    # Spelled explicitly for the same reason as on SH-2A: the cspec lists the
    # float return fr0 ahead of r0, so `arch.ret_offset` is the wrong register.
    RETURN_VAL = angr.calling_conventions.SimRegArg(SH4_RETURN_VALUE_REGISTER, 4)
    RETURN_ADDR = angr.calling_conventions.SimRegArg(SH4_RETURN_ADDRESS_REGISTER, 4)


class SimCCSuperH4BE(SimCCSuperH4):
    ARCH = archinfo.ArchPcode(SH4_BE_PCODE_LANGUAGE)  # type: ignore


class SimCCSuperH4EL(SimCCSuperH4):
    ARCH = archinfo.ArchPcode(SH4_EL_PCODE_LANGUAGE)  # type: ignore


angr.calling_conventions.register_default_cc(SH4_BE_PCODE_LANGUAGE, SimCCSuperH4BE)
angr.calling_conventions.register_default_cc(SH4_EL_PCODE_LANGUAGE, SimCCSuperH4EL)
