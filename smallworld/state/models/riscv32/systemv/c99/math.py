from ....c99.math import Fabs
from ..systemv import RiscV32SysVModel


class RiscV32SysVFabs(Fabs, RiscV32SysVModel):
    pass


__all__ = ["RiscV32SysVFabs"]
