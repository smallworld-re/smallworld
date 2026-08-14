import typing

import angr
import archinfo

from ....platforms import Architecture, Byteorder
from ....platforms.defs.superh import (
    SH2A_FLOAT_ARGUMENT_REGISTERS,
    SH2A_INTEGER_ARGUMENT_REGISTERS,
    SH2A_PROGRAM_COUNTER_REGISTER,
    SH2A_REGISTER_ALIASES,
    SH2A_RETURN_ADDRESS_REGISTER,
    SH2A_RETURN_VALUE_REGISTER,
    SH2A_STATUS_REGISTER,
)
from .machdef import GhidraMachineDef

SH2A_PCODE_LANGUAGE = "SuperH:BE:32:SH-2A"


class SH2AFPUMachineDef(GhidraMachineDef):
    arch = Architecture.SUPERH_SH2A_FPU
    byteorder = Byteorder.BIG
    pcode_language = SH2A_PCODE_LANGUAGE

    # SuperH is a delay-slot ISA, but unlike the VEX-backed MIPS machdefs this
    # one is safe to single-step: sleigh lifts a branch and its delay slot as one
    # unit, emitting the delay-slot semantics before the transfer, so a single
    # step covers both.
    supports_single_step = True

    # `archinfo.ArchPcode` lowercases every sleigh register name, and SH-2A's
    # spec is already lowercase, so this is an identity map apart from the
    # aliases. ArchPcode synthesizes `sp` (onto r15) and `ip` (onto pc) but not
    # `fp`/`ra`/`lr`, so each alias resolves to the architectural register it
    # names rather than relying on that synthesis.
    _registers: typing.Dict[str, str] = {
        # *** General-Purpose Registers ***
        **{f"r{i}": f"r{i}" for i in range(0, 16)},
        **SH2A_REGISTER_ALIASES,
        # *** Control Registers ***
        SH2A_PROGRAM_COUNTER_REGISTER: SH2A_PROGRAM_COUNTER_REGISTER,
        SH2A_STATUS_REGISTER: SH2A_STATUS_REGISTER,
        "pr": "pr",
        "gbr": "gbr",
        "vbr": "vbr",
        "tbr": "tbr",
        "mach": "mach",
        "macl": "macl",
        # *** Floating-Point Registers ***
        **{f"dr{i}": f"dr{i}" for i in range(0, 16, 2)},
        **{f"fr{i}": f"fr{i}" for i in range(0, 16)},
        "fpscr": "fpscr",
        "fpul": "fpul",
    }


class SimCCSH2AFPU(angr.calling_conventions.SimCC):
    ARG_REGS = list(SH2A_INTEGER_ARGUMENT_REGISTERS)
    FP_ARG_REGS = list(SH2A_FLOAT_ARGUMENT_REGISTERS)
    # Spelled explicitly rather than left to `ArchPcode`: it derives
    # `arch.ret_offset` from the first `<output><pentry>` in the compiler spec,
    # and `superh2a.cspec` lists the float return fr0 ahead of r0.
    RETURN_VAL = angr.calling_conventions.SimRegArg(SH2A_RETURN_VALUE_REGISTER, 4)
    RETURN_ADDR = angr.calling_conventions.SimRegArg(SH2A_RETURN_ADDRESS_REGISTER, 4)
    ARCH = archinfo.ArchPcode(SH2A_PCODE_LANGUAGE)  # type: ignore


angr.calling_conventions.register_default_cc(SH2A_PCODE_LANGUAGE, SimCCSH2AFPU)
