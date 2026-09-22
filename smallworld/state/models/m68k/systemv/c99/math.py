from ....c99.math import Fabs
from ..systemv import M68KSysVModel


class M68KSysVFabs(Fabs, M68KSysVModel):
    pass


__all__ = ["M68KSysVFabs"]
