import typing

from ....platforms import Architecture, Byteorder
from .machdef import GhidraMachineDef


class TriCoreMachineDef(GhidraMachineDef):
    arch = Architecture.TRICORE
    byteorder = Byteorder.LITTLE
    language_id = "tricore:LE:32:default"

    _registers: typing.Dict[str, typing.Optional[str]] = {
        **{f"a{i}": f"a{i}" for i in range(0, 16)},
        **{f"d{i}": f"d{i}" for i in range(0, 16)},
        "pc": "PC",
        "psw": "PSW",
        "sp": "a10",
        "ra": "a11",
        "lr": "a11",
    }
