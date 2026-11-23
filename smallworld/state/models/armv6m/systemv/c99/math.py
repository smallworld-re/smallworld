from ....c99.math import Fabs
from ..systemv import ArmV6MSysVModel


class ArmV6MSysVFabs(Fabs, ArmV6MSysVModel):
    pass


__all__ = ["ArmV6MSysVFabs"]
