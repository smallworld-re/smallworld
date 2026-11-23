from ....c99.math import Fabs
from ..systemv import ArmV8RSysVModel


class ArmV8RSysVFabs(Fabs, ArmV8RSysVModel):
    pass


__all__ = ["ArmV8RSysVFabs"]
