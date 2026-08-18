import typing

from ....platforms import Architecture, Byteorder
from .machdef import GhidraMachineDef


class XTensaMachineDef(GhidraMachineDef):
    arch = Architecture.XTENSA
    _registers: typing.Dict[str, typing.Optional[str]] = {}
    _registers |= {f"a{i}": f"a{i}" for i in range(0, 16)}
    _registers |= {"pc": "pc", "sar": "sar", "sp": "a1"}


class XTensaELMachineDef(XTensaMachineDef):
    byteorder = Byteorder.LITTLE


class XTensaBEMachineDef(XTensaMachineDef):
    byteorder = Byteorder.BIG
    # No big-endian Xtensa PlatformDef exists yet, so this machine def keeps
    # its literal language id until one is added; every other machdef sources
    # it from PlatformDef.ghidra_language_id.
    language_id = "Xtensa:BE:32:default"
