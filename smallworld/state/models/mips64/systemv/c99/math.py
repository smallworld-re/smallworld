from ....c99.math import Fabs
from ..systemv import MIPS64SysVModel


class MIPS64SysVFabs(Fabs, MIPS64SysVModel):
    pass


__all__ = ["MIPS64SysVFabs"]
