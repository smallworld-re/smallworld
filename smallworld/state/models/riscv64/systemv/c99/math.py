from ....c99.math import Fabs
from ..systemv import RiscV64SysVModel


class RiscV64SysVFabs(Fabs, RiscV64SysVModel):
    pass


__all__ = ["RiscV64SysVFabs"]
