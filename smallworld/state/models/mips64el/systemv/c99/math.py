from ....c99.math import Fabs
from ..systemv import MIPS64ELSysVModel


class MIPS64ELSysVFabs(Fabs, MIPS64ELSysVModel):
    pass


__all__ = ["MIPS64ELSysVFabs"]
