from ....c99.math import Fabs
from ..systemv import PowerPC64SysVModel


class PowerPC64SysVFabs(Fabs, PowerPC64SysVModel):
    pass


__all__ = ["PowerPC64SysVFabs"]
