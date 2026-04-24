from ....platforms import Architecture, Byteorder
from ....platforms.defs.tricore import (
    TRICORE_PROGRAM_COUNTER_REGISTER,
    TRICORE_REGISTER_ALIASES,
    TRICORE_STATUS_REGISTER,
)
from .machdef import PandaMachineDef


class TriCoreMachineDef(PandaMachineDef):
    arch = Architecture.TRICORE
    byteorder = Byteorder.LITTLE

    panda_arch = "tricore"
    machine = "KIT_AURIX_TC277_TRB"
    cpu = "tc27x"
    _registers = {
        **{f"d{i}": f"d{i}" for i in range(16)},
        **{f"a{i}": f"a{i}" for i in range(16)},
        **TRICORE_REGISTER_ALIASES,
        TRICORE_PROGRAM_COUNTER_REGISTER: TRICORE_PROGRAM_COUNTER_REGISTER,
        TRICORE_STATUS_REGISTER: TRICORE_STATUS_REGISTER,
    }
