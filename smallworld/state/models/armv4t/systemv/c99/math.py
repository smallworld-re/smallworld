from ....c99.math import Fabs
from ..systemv import ArmV4TSysVModel


class ArmV4TSysVFabs(Fabs, ArmV4TSysVModel):
    pass


__all__ = ["ArmV4TSysVFabs"]
