from ....c99.math import Fabs
from ..systemv import ArmV8RBESysVModel


class ArmV8RBESysVFabs(Fabs, ArmV8RBESysVModel):
    pass


__all__ = ["ArmV8RBESysVFabs"]
