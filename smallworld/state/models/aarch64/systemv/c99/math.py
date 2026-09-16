from ....c99.math import Fabs
from ..systemv import AArch64SysVModel


class AArch64SysVFabs(Fabs, AArch64SysVModel):
    pass


__all__ = ["AArch64SysVFabs"]
