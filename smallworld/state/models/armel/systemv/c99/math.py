from ....c99.math import Fabs
from ..systemv import ArmELSysVModel


class ArmELSysVFabs(Fabs, ArmELSysVModel):
    pass


__all__ = ["ArmELSysVFabs"]
