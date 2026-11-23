from ....c99.math import Fabs
from ..systemv import ArmV7EMSysVModel


class ArmV7EMSysVFabs(Fabs, ArmV7EMSysVModel):
    pass


__all__ = ["ArmV7EMSysVFabs"]
