from ....c99.math import Fabs
from ..systemv import SPARC32SysVModel


class SPARC32SysVFabs(Fabs, SPARC32SysVModel):
    pass


__all__ = ["SPARC32SysVFabs"]
