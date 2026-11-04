import typing

import angr
import archinfo

from ....platforms import Architecture, Byteorder
from ....platforms.defs.v850 import (
    V850_ARGUMENT_REGISTERS,
    V850_GENERAL_REGISTERS,
    V850_NAMED_REGISTERS,
    V850_PROGRAM_COUNTER_REGISTER,
    V850_RETURN_ADDRESS_REGISTER,
    V850_RETURN_VALUE_REGISTER,
    V850_SYSTEM_REGISTERS,
)
from .machdef import GhidraMachineDef

V850_PCODE_LANGUAGE = "V850:LE:32:default"


class V850MachineDef(GhidraMachineDef):
    arch = Architecture.V850
    byteorder = Byteorder.LITTLE
    pcode_language = V850_PCODE_LANGUAGE

    # angr names p-code registers as Ghidra does, in lower case.
    _registers = {
        **{name: name for name in V850_GENERAL_REGISTERS},
        **{number: name for name, number in V850_NAMED_REGISTERS.items()},
        V850_PROGRAM_COUNTER_REGISTER: V850_PROGRAM_COUNTER_REGISTER,
        **{name: name for name in V850_SYSTEM_REGISTERS},
    }


class SimCCV850(angr.calling_conventions.SimCC):
    """GCC's V850 calling convention.

    The first four word arguments go in r6 to r9, results come back in r10
    (and r11), and the return address is in lp.
    """

    ARG_REGS = list(V850_ARGUMENT_REGISTERS)
    FP_ARG_REGS: typing.List[str] = []
    RETURN_VAL = angr.calling_conventions.SimRegArg(V850_RETURN_VALUE_REGISTER, 4)
    RETURN_ADDR = angr.calling_conventions.SimRegArg(V850_RETURN_ADDRESS_REGISTER, 4)
    ARCH = archinfo.ArchPcode(V850_PCODE_LANGUAGE)  # type: ignore


angr.calling_conventions.register_default_cc(V850_PCODE_LANGUAGE, SimCCV850)
