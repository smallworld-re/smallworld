from ....c99.math import Fabs
from ..systemv import ArmV7ASysVModel


class ArmV7ASysVFabs(Fabs, ArmV7ASysVModel):
    pass


__all__ = ["ArmV7ASysVFabs"]
