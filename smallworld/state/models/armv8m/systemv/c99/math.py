from ....c99.math import Fabs
from ..systemv import ArmV8MSysVModel


class ArmV8MSysVFabs(Fabs, ArmV8MSysVModel):
    pass


__all__ = ["ArmV8MSysVFabs"]
