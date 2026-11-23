from ....c99.math import Fabs
from ..systemv import ArmV5TSysVModel


class ArmV5TSysVFabs(Fabs, ArmV5TSysVModel):
    pass


__all__ = ["ArmV5TSysVFabs"]
