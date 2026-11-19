import typing

from ....platforms import Architecture, Byteorder
from ....platforms.defs.v850 import (
    V850_GENERAL_REGISTERS,
    V850_NAMED_REGISTERS,
    V850_PROGRAM_COUNTER_REGISTER,
    V850_SYSTEM_REGISTERS,
)
from .machdef import GhidraMachineDef


class V850MachineDef(GhidraMachineDef):
    arch = Architecture.V850
    byteorder = Byteorder.LITTLE

    # Ghidra names the general registers in lower case and the pc and system
    # registers in upper case.
    _registers: typing.Dict[str, typing.Optional[str]] = {
        **{name: name for name in V850_GENERAL_REGISTERS},
        **{number: name for name, number in V850_NAMED_REGISTERS.items()},
        V850_PROGRAM_COUNTER_REGISTER: "PC",
        **{name: name.upper() for name in V850_SYSTEM_REGISTERS},
    }
