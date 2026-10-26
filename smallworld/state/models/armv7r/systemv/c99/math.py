from ....c99.math import Fabs
from ..systemv import ArmV7RSysVModel


class ArmV7RSysVFabs(Fabs, ArmV7RSysVModel):
    pass


__all__ = ["ArmV7RSysVFabs"]
