from ....c99.math import Fabs
from ..systemv import ArmV7MSysVModel


class ArmV7MSysVFabs(Fabs, ArmV7MSysVModel):
    pass


__all__ = ["ArmV7MSysVFabs"]
