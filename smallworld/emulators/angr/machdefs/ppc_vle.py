import typing

import angr
import archinfo

from ....platforms import Architecture, Byteorder
from ....platforms.defs import PowerPC32VLE
from .machdef import GhidraMachineDef

PPC_VLE_PCODE_LANGUAGE = "PowerPC:BE:32:e200"


class PowerPC32VLEMachineDef(GhidraMachineDef):
    """angr machine definition for PowerPC e200 with VLE, using Ghidra's
    p-code.

    VEX, which runs the other PowerPC machines, has no VLE decoder. The
    e200 language decodes VLE by default and names its registers as
    SmallWorld does.
    """

    arch = Architecture.POWERPC32_VLE
    byteorder = Byteorder.BIG
    pcode_language = PPC_VLE_PCODE_LANGUAGE

    _registers: typing.Dict[str, typing.Optional[str]] = {  # type: ignore[assignment]
        **{name: name for name in PowerPC32VLE().registers},
        "sp": "r1",
        "bp": "r31",
        # NOTE: The Ghidra machine definition leaves msr out too.
        "msr": None,
    }


class SimCCPowerPC32VLE(angr.calling_conventions.SimCC):
    """PowerPC EABI calling convention.

    Integer arguments go in r3 through r10, results come back in r3 (and
    r4), and the return address is in lr.
    """

    ARG_REGS = [f"r{i}" for i in range(3, 11)]
    FP_ARG_REGS: typing.List[str] = []
    RETURN_VAL = angr.calling_conventions.SimRegArg("r3", 4)
    OVERFLOW_RETURN_VAL = angr.calling_conventions.SimRegArg("r4", 4)
    RETURN_ADDR = angr.calling_conventions.SimRegArg("lr", 4)
    ARCH = archinfo.ArchPcode(PPC_VLE_PCODE_LANGUAGE)  # type: ignore


angr.calling_conventions.register_default_cc(PPC_VLE_PCODE_LANGUAGE, SimCCPowerPC32VLE)
