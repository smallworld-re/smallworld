from ....c99.math import Fabs
from ..systemv import MicroMIPSELSysVModel


class MicroMIPSELSysVFabs(Fabs, MicroMIPSELSysVModel):
    pass


__all__ = ["MicroMIPSELSysVFabs"]
