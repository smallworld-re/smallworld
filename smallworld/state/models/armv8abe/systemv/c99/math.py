from ....c99.math import Fabs
from ..systemv import ArmV8ABESysVModel


class ArmV8ABESysVFabs(Fabs, ArmV8ABESysVModel):
    pass


__all__ = ["ArmV8ABESysVFabs"]
