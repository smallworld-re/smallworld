from ....c99.math import Fabs
from ..systemv import MIPSELSysVModel


class MIPSELSysVFabs(Fabs, MIPSELSysVModel):
    pass


__all__ = ["MIPSELSysVFabs"]
