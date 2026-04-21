from ....platforms import Architecture, Byteorder
from .machdef import PandaMachineDef


class TriCoreMachineDef(PandaMachineDef):
    arch = Architecture.TRICORE
    byteorder = Byteorder.LITTLE

    panda_arch = "tricore"
    machine = "KIT_AURIX_TC277_TRB"
    cpu = "tc27x"

    def __init__(self):
        self._registers = {f"d{i}": f"d{i}" for i in range(16)}
        self._registers |= {f"a{i}": f"a{i}" for i in range(16)}
        self._registers |= {
            "sp": "a10",
            "ra": "a11",
            "lr": "a11",
            "pc": "pc",
            "psw": "psw",
        }
