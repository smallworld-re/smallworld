from ....c99.math import Fabs
from ..systemv import LoongArch64SysVModel


class LoongArch64SysVFabs(Fabs, LoongArch64SysVModel):
    pass


__all__ = ["LoongArch64SysVFabs"]
