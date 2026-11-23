from ....c99.math import Fabs
from ..systemv import ArmV8ASysVModel


class ArmV8ASysVFabs(Fabs, ArmV8ASysVModel):
    pass


__all__ = ["ArmV8ASysVFabs"]
