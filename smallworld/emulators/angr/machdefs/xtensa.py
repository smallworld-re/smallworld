from ....platforms import Architecture, Byteorder
from .machdef import PcodeMachineDef


class XTensaMachineDef(PcodeMachineDef):
    arch = Architecture.XTENSA
    _registers = {f"a{i}": f"a{i}" for i in range(0, 16)} | {"pc": "pc", "sar": "sar"}
    pc_reg = "pc"


class XTensaELMachineDef(XTensaMachineDef):
    byteorder = Byteorder.LITTLE
    pcode_language = "Xtensa:LE:32:default"


class XTensaBEMachineDef(XTensaMachineDef):
    byteorder = Byteorder.BIG
    pcode_language = "Xtensa:BE:32:default"
