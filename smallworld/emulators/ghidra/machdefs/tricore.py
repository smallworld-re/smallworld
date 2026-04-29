import typing

from ....platforms import Architecture, Byteorder
from ....platforms.defs.tricore import (
    TRICORE_PROGRAM_COUNTER_REGISTER,
    TRICORE_REGISTER_ALIASES,
    TRICORE_STATUS_REGISTER,
)
from .machdef import GhidraMachineDef


class TriCoreMachineDef(GhidraMachineDef):
    arch = Architecture.TRICORE
    byteorder = Byteorder.LITTLE
    language_id = "tricore:LE:32:default"

    _registers: typing.Dict[str, typing.Optional[str]] = {
        **{f"a{i}": f"a{i}" for i in range(0, 16)},
        **{f"d{i}": f"d{i}" for i in range(0, 16)},
        **TRICORE_REGISTER_ALIASES,
        TRICORE_PROGRAM_COUNTER_REGISTER: "PC",
        TRICORE_STATUS_REGISTER: "PSW",
    }
