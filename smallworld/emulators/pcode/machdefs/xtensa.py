import typing

from ....platforms import Architecture, Byteorder
from .machdef import PcodeMachineDef


class XTensaMachineDef(PcodeMachineDef):
    arch = Architecture.XTENSA
    _registers: typing.Dict[str, typing.Optional[str]] = {}
    _registers |= {f"a{i}": f"a{i}" for i in range(0, 16)}
    _registers |= {"pc": "pc", "sar": "sar"}
    pc_reg = "pc"
    address_size = 4


class XTensaELMachineDef(XTensaMachineDef):
    byteorder = Byteorder.LITTLE
    language_id = "Xtensa:LE:32:default"


class XTensaBEMachineDef(XTensaMachineDef):
    byteorder = Byteorder.BIG
    language_id = "Xtensa:BE:32:default"
