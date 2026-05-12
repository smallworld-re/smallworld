import unicorn
from unicorn import tricore_const

from ....platforms import Architecture, Byteorder
from .machdef import UnicornMachineDef


class TriCoreMachineDef(UnicornMachineDef):
    arch = Architecture.TRICORE
    byteorder = Byteorder.LITTLE

    uc_arch = unicorn.UC_ARCH_TRICORE
    uc_mode = unicorn.UC_MODE_LITTLE_ENDIAN

    _registers = {
        **{f"a{i}": getattr(tricore_const, f"UC_TRICORE_REG_A{i}") for i in range(16)},
        **{f"d{i}": getattr(tricore_const, f"UC_TRICORE_REG_D{i}") for i in range(16)},
        "pc": tricore_const.UC_TRICORE_REG_PC,
        "psw": tricore_const.UC_TRICORE_REG_PSW,
        "sp": tricore_const.UC_TRICORE_REG_SP,
        "ra": tricore_const.UC_TRICORE_REG_LR,
        "lr": tricore_const.UC_TRICORE_REG_LR,
    }
